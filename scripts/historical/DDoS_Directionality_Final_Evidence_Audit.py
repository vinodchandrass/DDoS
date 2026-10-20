"""Read-only PCAP/CSV directionality, segmentation, and evidence-freeze audit.
Run: python DDoS_Directionality_Final_Evidence_Audit.py
Dependencies: pandas, scapy. Frozen input hashes enforced.
This is exploratory reconstruction, NOT original exporter reproduction.
"""
import argparse, hashlib, json, math
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP

PCAP_SHA='5ca6b0bd8ba7abf09399adffb4bb86505c8dd228273316bbd53e030acfeb5c56'
CSV_SHA='b24bf115c226025a476e1d65efca23e8c43186932ea484881983f26dc9128d59'
CONFIGS=[('idle_0p001',.001,120,False),('idle_0p01',.01,120,False),('idle_0p1',.1,120,False),('idle_1',1,120,False),('idle_5',5,120,False),('idle_15',15,120,False),('idle_30',30,120,False),('idle_60',60,120,False),('idle_120',120,120,False),('idle_120_active_600',120,600,False),('rst_terminated',120,120,True),('rst_terminated_idle_1',1,120,True)]

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()

def k(a,b,c,d):return (str(a),int(b),str(c),int(d))

def segment(events,idle,active,rst):
    chunks=[];cur=[]
    for ev in events:
        if cur and (ev[0]-cur[-1][0]>idle or ev[0]-cur[0][0]>active):
            chunks.append(cur);cur=[]
        cur.append(ev)
        if rst and ev[2]&4:
            chunks.append(cur);cur=[]
    if cur:chunks.append(cur)
    return chunks

def sig(seg):
    a,b=seg[0][0],seg[-1][0]
    f=sum(x[1]==0 for x in seg);r=len(seg)-f
    return {'start_epoch':a,'duration_us':(b-a)*1e6,'fwd':f,'bwd':r,'total':len(seg),
            'syn':sum(bool(x[2]&2) for x in seg),'rst':sum(bool(x[2]&4) for x in seg),
            'ack':sum(bool(x[2]&16) for x in seg)}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--pcap',required=True)
    p.add_argument('--csv',required=True)
    p.add_argument('--out',required=True)
    a=p.parse_args(); out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    pcap,csv=Path(a.pcap),Path(a.csv)
    observed={'pcap_sha256':sha(pcap),'csv_sha256':sha(csv)}
    if observed['pcap_sha256']!=PCAP_SHA or observed['csv_sha256']!=CSV_SHA:
        raise RuntimeError('FROZEN INPUT HASH MISMATCH: aborting audit')
    df=pd.read_csv(csv,low_memory=False)
    attacks=df[df['Label'].astype(str).str.upper().eq('DDOS')]
    targets={};excluded=[]
    for idx,r in attacks.iterrows():
        try:
            if int(r['Protocol'])!=6:
                excluded.append({'row_index':int(idx),'reason':'non_TCP'});continue
            key=k(r['Src IP'],r['Src Port'],r['Dst IP'],r['Dst Port'])
            if key in targets:raise RuntimeError('Duplicate attack tuple: row pairing ambiguous')
            t=datetime.strptime(str(r['Timestamp']),'%d-%m-%Y %H:%M').replace(tzinfo=timezone.utc).timestamp()-19800
            targets[key]={'row_index':int(idx),'csv_fwd':int(r['Tot Fwd Pkts']),
                          'csv_bwd':int(r['Tot Bwd Pkts']),'csv_dur':float(r['Flow Duration']),
                          'start_minute_utc':t}
        except (ValueError,TypeError,KeyError) as e:excluded.append({'row_index':int(idx),'reason':str(e)})
    reverse={k(q[2],q[3],q[0],q[1]):q for q in targets}
    ambiguous=set(targets)&set(reverse)
    if ambiguous:raise RuntimeError('Ambiguous reverse tuples; cannot assign packet directions')
    events=defaultdict(list);count=0;relevant=0;errors=0
    print('Reading PCAP once...',flush=True)
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            count+=1
            try:
                if IP not in pkt or TCP not in pkt:continue
                ip,tcp=pkt[IP],pkt[TCP];q=k(ip.src,tcp.sport,ip.dst,tcp.dport)
                if q in targets: anchor=q;direction=0
                elif q in reverse:anchor=reverse[q];direction=1
                else:continue
                events[anchor].append((float(pkt.time),direction,int(tcp.flags)));relevant+=1
            except Exception:errors+=1
            if count%1000000==0:print('Packets:',count,flush=True)
    comparisons=[];details=[];summary=[]
    for name,idle,active,rst in CONFIGS:
        print('Evaluating',name,flush=True)
        counts=Counter();group=defaultdict(Counter)
        for q,r in targets.items():
            if q not in events:continue
            ss=[sig(s) for s in segment(sorted(events[q]),idle,active,rst)]
            eligible=[s for s in ss if r['start_minute_utc']<=s['start_epoch']<r['start_minute_utc']+60]
            tol=max(10,.05*max(r['csv_dur'],1))
            candidates=[]
            for s in eligible:
                dur=abs(s['duration_us']-r['csv_dur'])<=tol
                original=(s['fwd']==r['csv_fwd'] and s['bwd']==r['csv_bwd'])
                swapped=(s['fwd']==r['csv_bwd'] and s['bwd']==r['csv_fwd'])
                total=(s['total']==r['csv_fwd']+r['csv_bwd'])
                candidates.append((s,dur,original,swapped,total))
            def hits(predicate):return [s for s,d,o,w,t in candidates if predicate(d,o,w,t)]
            orig=hits(lambda d,o,w,t:o and d)
            swap=hits(lambda d,o,w,t:w and d)
            anytotal=hits(lambda d,o,w,t:t and d)
            best=min(candidates,key=lambda x:(abs(x[0]['duration_us']-r['csv_dur']),abs(x[0]['total']-r['csv_fwd']-r['csv_bwd']))) if candidates else None
            stratum='short_le_1s' if r['csv_dur']<=1e6 else 'long_gt_1s'
            flags={'eligible_start':bool(eligible),'original_joint':bool(orig),'swapped_joint':bool(swap),
                   'either_joint':bool(orig or swap),'total_duration_joint':bool(anytotal),
                   'duration_only':any(d for s,d,o,w,t in candidates),
                   'unique_swapped_joint':len(swap)==1,'unique_original_joint':len(orig)==1}
            counts.update({x:int(y) for x,y in flags.items()});group[stratum].update({x:int(y) for x,y in flags.items()})
            counts['rows']+=1;group[stratum]['rows']+=1
            if name in ('idle_0p1','rst_terminated','idle_120'):
                details.append({'configuration':name,'row_index':r['row_index'],'stratum':stratum,
                    'csv_fwd':r['csv_fwd'],'csv_bwd':r['csv_bwd'],'csv_duration_us':r['csv_dur'],
                    'eligible_segments':len(eligible),'original_joint_candidates':len(orig),
                    'swapped_joint_candidates':len(swap),'total_duration_joint_candidates':len(anytotal),
                    'best_duration_error_us':round(abs(best[0]['duration_us']-r['csv_dur']),3) if best else None,
                    'best_fwd':best[0]['fwd'] if best else None,'best_bwd':best[0]['bwd'] if best else None,
                    'best_total':best[0]['total'] if best else None})
        for st,ct in [('all',counts)]+sorted(group.items()):
            summary.append({'configuration':name,'idle_s':idle,'active_s':active,'rst_termination':rst,
                            'stratum':st,**dict(ct)})
    pd.DataFrame(summary).fillna(0).to_csv(out/'directionality_candidate_comparison.csv',index=False)
    pd.DataFrame(details).to_csv(out/'directionality_row_diagnostics.csv',index=False)
    evidence={'scope':'Read-only exploratory directionality/timeout diagnostic; not authenticated exporter reproduction',
              'source_hashes':observed,'packets_read':count,'relevant_packets':relevant,'packet_processing_errors':errors,
              'attack_csv_rows':len(attacks),'matched_attack_tuples':len(events),'excluded_rows':excluded,
              'candidate_count':len(CONFIGS),'time_assumption':'CSV minute interpreted UTC+05:30',
              'duration_assumption':'Flow Duration interpreted as microseconds',
              'joint_match_tolerance':'max(10 microseconds, 5% of CSV duration)',
              'row_matching_rule':'At least one same-tuple reconstructed segment starting within recorded minute; no one-to-one assignment guaranteed',
              'limitations':['No original exporter source/configuration','Rst termination is a candidate approximation',
                             'Repeated endpoint tuples and multiple candidate segments can inflate existential matching',
                             'No original feature-vector reconstruction','No independent inference parity'],
              'summary':summary}
    (out/'directionality_evidence_summary.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    manifest={'inputs':observed,'outputs':{p.name:sha(p) for p in sorted(out.glob('*')) if p.is_file() and p.name!='evidence_manifest.json'},
              'interpretation':'Exploratory. Freeze report is not an authenticated original exporter reproduction.'}
    (out/'evidence_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'status':'COMPLETE','out':str(out),'matched_tuples':len(events),'files':list(manifest['outputs'])},indent=2))
if __name__=='__main__':main()