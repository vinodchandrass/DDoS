"""Read-only PCAP/CSV provenance audit. Requires pandas and scapy.
Run: python DDoS_PCAP_Time_Flow_Reconciliation.py
"""
import json, math, ast, hashlib, argparse
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
import pandas as pd
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--pcap",required=True)
    p.add_argument("--csv",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    PCAP=Path(args.pcap)
    CSV=Path(args.csv)
    OUT=Path(args.out)
    OUT.mkdir(parents=True,exist_ok=True)

    csv=pd.read_csv(CSV,low_memory=False).dropna(subset=['Label']).copy()
    csv['parsed_time']=pd.to_datetime(csv['Timestamp'],format='%d-%m-%Y %H:%M',errors='coerce')
    csv['row_index']=csv.index
    attack=csv[csv['Label'].astype(str).str.upper()=='DDOS'].copy()

    def key(ip1,p1,ip2,p2):
        return (str(ip1),int(p1),str(ip2),int(p2))

    def key_for_csv(row):
        try: return key(row['Src IP'],row['Src Port'],row['Dst IP'],row['Dst Port'])
        except (ValueError,TypeError,OverflowError): return None

    attack['tuple_key']=attack.apply(key_for_csv,axis=1)
    keys=set(attack['tuple_key'].dropna())
    # Store only tuples present in the attack CSV, reducing memory substantially.
    seen={k:{'count':0,'first':None,'last':None,'syn':0,'ack':0,'rst':0,'fin':0,
             'reverse_count':0,'reverse_first':None,'reverse_last':None} for k in keys}
    first_global=None;last_global=None;total=0;bad=0
    with PcapReader(str(PCAP)) as reader:
        for pkt in reader:
            total+=1
            try:
                if IP not in pkt or TCP not in pkt: continue
                ip=pkt[IP];t=pkt[TCP];ts=float(pkt.time)
                first_global=ts if first_global is None else min(first_global,ts)
                last_global=ts if last_global is None else max(last_global,ts)
                k=key(ip.src,t.sport,ip.dst,t.dport)
                if k in seen:
                    s=seen[k];s['count']+=1
                    s['first']=ts if s['first'] is None else min(s['first'],ts)
                    s['last']=ts if s['last'] is None else max(s['last'],ts)
                    f=int(t.flags)
                    for flag,bit in [('syn',2),('ack',16),('rst',4),('fin',1)]:
                        if f&bit:s[flag]+=1
                rk=key(ip.dst,t.dport,ip.src,t.sport)
                if rk in seen:
                    s=seen[rk];s['reverse_count']+=1
                    s['reverse_first']=ts if s['reverse_first'] is None else min(s['reverse_first'],ts)
                    s['reverse_last']=ts if s['reverse_last'] is None else max(s['reverse_last'],ts)
            except Exception:bad+=1
            if total%1000000==0:print(f'Processed {total:,} packets',flush=True)

    # CSV timestamps are minute-resolution, and the timezone is not documented.
    # Evaluate candidate UTC offsets rather than silently asserting one.
    rows=[]
    for _,r in attack.iterrows():
        k=r['tuple_key'];s=seen.get(k) if k is not None else None
        rec={'row_index':int(r['row_index']),'label':r['Label'],'flow_id':r.get('Flow ID'),
             'src_ip':r['Src IP'],'src_port':r['Src Port'],'dst_ip':r['Dst IP'],
             'dst_port':r['Dst Port'],'protocol':r['Protocol'],'csv_timestamp':r['Timestamp'],
             'csv_forward_packets':r['Tot Fwd Pkts'],'csv_backward_packets':r['Tot Bwd Pkts'],
             'csv_duration':r['Flow Duration'],'tuple_present':bool(s and s['count']>0)}
        if s and s['count']:
            rec.update({'pcap_forward_packets_all':s['count'],
                        'pcap_reverse_packets_all':s['reverse_count'],
                        'pcap_first_utc':datetime.fromtimestamp(s['first'],timezone.utc).isoformat(),
                        'pcap_last_utc':datetime.fromtimestamp(s['last'],timezone.utc).isoformat(),
                        'pcap_tuple_span_seconds':s['last']-s['first'],
                        'pcap_syn_count':s['syn'],'pcap_ack_count':s['ack'],
                        'pcap_rst_count':s['rst'],'pcap_fin_count':s['fin']})
            if pd.notna(r['parsed_time']):
                # Local CSV time assumed at candidate UTC offset, truncated to minute.
                for hours in [0,5.5]:
                    inferred_utc=(r['parsed_time'].to_pydatetime()-timedelta(hours=hours)).replace(tzinfo=timezone.utc)
                    rec[f'time_gap_seconds_offset_{hours}']=s['first']-inferred_utc.timestamp()
                    rec[f'pcap_first_within_csv_minute_offset_{hours}']=0<=rec[f'time_gap_seconds_offset_{hours}']<60
            try:
                rec['csv_fwd_count_le_pcap_total']=float(r['Tot Fwd Pkts'])<=s['count']
                rec['csv_bwd_count_le_pcap_total']=float(r['Tot Bwd Pkts'])<=s['reverse_count']
            except (ValueError,TypeError):pass
        rows.append(rec)

    result=pd.DataFrame(rows)
    result.to_csv(OUT/'attack_tuple_time_reconciliation.csv',index=False)
    summary={
     'scope':'Descriptive provenance audit only; does not reproduce the CSV flow exporter or model inference',
     'pcap_path':str(PCAP),'csv_path':str(CSV),
     'pcap_packets_read':total,'pcap_packet_processing_errors':bad,
     'csv_rows_labelled':len(csv),'attack_rows':len(attack),
     'attack_rows_with_tuple_in_pcap':int(result['tuple_present'].sum()),
     'attack_rows_without_tuple_in_pcap':int((~result['tuple_present']).sum()),
     'attack_unique_tuple_keys':len(keys),
     'timestamp_offset_candidate_hours':[0,5.5],
     'csv_timestamp_precision':'minute',
     'pcap_global_first_utc':datetime.fromtimestamp(first_global,timezone.utc).isoformat() if first_global else None,
     'pcap_global_last_utc':datetime.fromtimestamp(last_global,timezone.utc).isoformat() if last_global else None,
     'unmatched_attack_rows':result.loc[~result['tuple_present'],['row_index','flow_id','csv_timestamp','protocol']].to_dict('records'),
    }
    for col in result.columns:
        if col.startswith('pcap_first_within_csv_minute_') or col.endswith('_le_pcap_total'):
            summary[col+'_true']=int(result[col].fillna(False).astype(bool).sum())
    for col in ['pcap_forward_packets_all','pcap_reverse_packets_all','pcap_tuple_span_seconds','pcap_syn_count','pcap_ack_count','pcap_rst_count','csv_forward_packets','csv_backward_packets','csv_duration']:
        if col in result:
            v=pd.to_numeric(result.loc[result['tuple_present'],col],errors='coerce').dropna()
            summary[col+'_summary']={'n':int(v.size),'min':float(v.min()) if v.size else None,'median':float(v.median()) if v.size else None,'max':float(v.max()) if v.size else None}
    (OUT/'reconciliation_summary.json').write_text(json.dumps(summary,indent=2,default=str),encoding='utf-8')
    print(json.dumps(summary,indent=2,default=str))
    print('Saved:',OUT)
if __name__=="__main__": main()
