"""Read-only diagnostic reconstruction of CSV/PCAP flow segmentation.
Requires: scapy, pandas. Runs on the research workstation holding the PCAP.
Never modifies the original CSV, PCAP, or model.
"""
from __future__ import annotations
import argparse, json, hashlib
from collections import defaultdict, Counter
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP

EXPECTED_PCAP_SHA = '5ca6b0bd8ba7abf09399adffb4bb86505c8dd228273316bbd53e030acfeb5c56'
EXPECTED_CSV_SHA = 'b24bf115c226025a476e1d65efca23e8c43186932ea484881983f26dc9128d59'

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''): h.update(b)
    return h.hexdigest()

def key(ip,port,ip2,port2):
    return (str(ip),int(port),str(ip2),int(port2))

def segments(events, idle, active):
    """Candidate inactivity/active timeouts, without protocol-specific termination rules."""
    out=[]; current=[]
    for ev in events:
        if current and (ev[0]-current[-1][0] > idle or ev[0]-current[0][0] > active):
            out.append(current); current=[]
        current.append(ev)
    if current:out.append(current)
    return out

def signature(s):
    # Each packet stored as (epoch, direction, flags). Direction 0 is CSV forward.
    a=s[0][0]; b=s[-1][0]
    return {'first_utc':datetime.fromtimestamp(a,timezone.utc).isoformat(),
            'duration_us':round((b-a)*1e6,3),
            'fwd':sum(e[1]==0 for e in s), 'bwd':sum(e[1]==1 for e in s),
            'packets':len(s), 'syn':sum(bool(e[2]&2) for e in s),
            'rst':sum(bool(e[2]&4) for e in s),
            'ack':sum(bool(e[2]&16) for e in s)}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--pcap',required=True)
    p.add_argument('--csv',required=True)
    p.add_argument('--out',required=True)
    p.add_argument('--skip-hash',action='store_true',help='Only if separately authenticated; hashes still recorded')
    args=p.parse_args()
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    pcap=Path(args.pcap);csv=Path(args.csv)
    ph=digest(pcap);ch=digest(csv)
    if not args.skip_hash and (ph!=EXPECTED_PCAP_SHA or ch!=EXPECTED_CSV_SHA):
        raise RuntimeError('Input SHA-256 differs from frozen source fingerprint. No analysis run.')
    df=pd.read_csv(csv,low_memory=False)
    attacks=df.loc[df['Label'].astype(str).str.upper().eq('DDOS')].copy()
    target={}; unmatched=[]
    for i,r in attacks.iterrows():
        try:
            if int(r['Protocol'])!=6: unmatched.append({'row_index':int(i),'reason':'non_TCP_protocol'});continue
            k=key(r['Src IP'],r['Src Port'],r['Dst IP'],r['Dst Port'])
            target[k]=(int(i),r)
        except (ValueError,TypeError):unmatched.append({'row_index':int(i),'reason':'invalid_tuple'})
    rev={key(k[2],k[3],k[0],k[1]):k for k in target}
    events=defaultdict(list);packets=0;relevant=0;parse_errors=0
    print('Reading PCAP once; retaining only target DDoS tuples...',flush=True)
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            packets+=1
            try:
                if IP not in pkt or TCP not in pkt:continue
                ip=pkt[IP];tcp=pkt[TCP]
                k=key(ip.src,tcp.sport,ip.dst,tcp.dport)
                if k in target: anchor=k;direction=0
                elif k in rev:anchor=rev[k];direction=1
                else:continue
                events[anchor].append((float(pkt.time),direction,int(tcp.flags)))
                relevant+=1
            except Exception:parse_errors+=1
            if packets%1000000==0:print(f'Processed {packets:,} packets',flush=True)
    # Candidate timeouts are hypotheses, not asserted exporter configuration.
    candidates=[(0.001,120),(0.01,120),(0.1,120),(1,120),(5,120),
                (15,120),(30,120),(60,120),(120,120),(120,600)]
    results=[];examples=[]
    for idle,active in candidates:
        exact=0;packet_match=0;duration_match=0;time_match=0;eligible=0;segment_total=0
        abs_duration_errors=[]
        for k,(row_idx,r) in target.items():
            ev=sorted(events.get(k,[]))
            if not ev:continue
            eligible+=1
            segs=segments(ev,idle,active);segment_total+=len(segs)
            csv_fwd=int(r['Tot Fwd Pkts']);csv_bwd=int(r['Tot Bwd Pkts'])
            csv_dur=float(r['Flow Duration'])
            try:
                # CSV minute interpreted as IST, converted to UTC.
                local=datetime.strptime(str(r['Timestamp']),'%d-%m-%Y %H:%M')
                csv_minute_utc=local.replace(tzinfo=timezone.utc).timestamp()-19800
            except ValueError:csv_minute_utc=None
            # Only segments whose start is in the CSV's recorded minute qualify.
            eligible_segs=[s for s in segs if csv_minute_utc is not None and
                           csv_minute_utc<=s[0][0]<csv_minute_utc+60]
            if eligible_segs:time_match+=1
            packet_segs=[s for s in eligible_segs if sum(e[1]==0 for e in s)==csv_fwd and
                         sum(e[1]==1 for e in s)==csv_bwd]
            if packet_segs:packet_match+=1
            if eligible_segs:
                best=min(eligible_segs,key=lambda s:abs((s[-1][0]-s[0][0])*1e6-csv_dur))
                err=abs((best[-1][0]-best[0][0])*1e6-csv_dur)
                abs_duration_errors.append(err)
                if err<=max(10,0.05*max(csv_dur,1)):duration_match+=1
            if any(abs((s[-1][0]-s[0][0])*1e6-csv_dur)<=max(10,0.05*max(csv_dur,1)) for s in packet_segs):exact+=1
            if idle==0.1 and active==120 and len(examples)<30:
                examples.append({'row_index':row_idx,'csv_fwd':csv_fwd,'csv_bwd':csv_bwd,
                    'csv_duration_us_assumed':csv_dur,'segments':len(segs),
                    'candidate_first_segments':[signature(s) for s in eligible_segs[:3]]})
        results.append({'idle_timeout_s':idle,'active_timeout_s':active,
            'eligible_attack_rows':eligible,'total_segments_across_matched_tuples':segment_total,
            'rows_with_start_minute_segment':time_match,'rows_with_packet_count_match':packet_match,
            'rows_with_duration_match_5pct_or_10us':duration_match,
            'rows_with_joint_packet_duration_match':exact,
            'median_absolute_duration_error_us':float(pd.Series(abs_duration_errors).median()) if abs_duration_errors else None})
    summary={'scope':'Exploratory diagnostic, NOT exporter reproduction',
        'pcap_sha256':ph,'csv_sha256':ch,'packets_read':packets,'relevant_packets':relevant,
        'packet_processing_errors':parse_errors,'attack_csv_rows':len(attacks),
        'tcp_attack_tuple_keys':len(target),'tcp_attack_tuple_keys_present':len(events),
        'excluded_attack_rows':unmatched,
        'timezone_hypothesis':'CSV timestamp UTC+05:30; minute precision',
        'duration_unit_hypothesis':'microseconds',
        'limitations':['No original exporter configuration','No TCP FIN/RST-based termination emulation',
                       'No packet payload or full feature-vector recreation',
                       'Multiple segments may share same tuple','Exploratory timeout grid; no model fitting'],
        'candidate_results':results}
    (out/'segmentation_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    pd.DataFrame(results).to_csv(out/'segmentation_timeout_comparison.csv',index=False)
    (out/'segmentation_examples.json').write_text(json.dumps(examples,indent=2),encoding='utf-8')
    print(json.dumps({'status':'COMPLETE','out':str(out),'best_candidate_by_joint_matches':
        max(results,key=lambda r:r['rows_with_joint_packet_duration_match'])},indent=2))

if __name__=='__main__':main()