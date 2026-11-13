"""Isolated Godpay demo orders. No access to live orders, verifiers or settlement hooks."""
import json
import math
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse


def register_sandbox(app, *, render, current_merchant, api_auth, rate_ok, client_ip, data_dir):
    path = Path(data_dir) / 'godpay_demo.db'
    path.parent.mkdir(parents=True, exist_ok=True)
    def connect():
        c = sqlite3.connect(str(path), timeout=15)
        c.row_factory = sqlite3.Row
        return c
    with connect() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS demo_orders (
            id TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, amount REAL NOT NULL,
            client_ref TEXT NOT NULL, status TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            auto_at INTEGER, paid_at INTEGER, utr TEXT)''')
        c.execute('CREATE INDEX IF NOT EXISTS demo_owner ON demo_orders(merchant_id,created_at)')
    def error(message, status=400):
        return JSONResponse({'success':False,'demo':True,'mode':'sandbox','error':message},status_code=status)
    def owner(request):
        # Supplied API credentials are always validated, never silently replaced by a cookie.
        if request.headers.get('x-api-key') or request.headers.get('authorization'):
            row, _, err = api_auth(request, limit=120, window=60)
            return (int(row['merchant_id']),None) if not err else (None,err)
        m = current_merchant(request)
        if not m:
            return None,error('Log in or send an X-Api-Key header.',401)
        if not rate_ok('demo:'+str(m['id'])+':'+client_ip(request),120,60):
            return None,error('Too many demo requests. Retry shortly.',429)
        if request.method == 'POST':
            origin=request.headers.get('origin')
            expected=urlsplit(str(request.base_url))
            if origin and urlsplit(origin).netloc != expected.netloc:
                return None,error('Cross-origin requests are not allowed.',403)
        return int(m['id']),None
    def get_order(oid, mid=None, token=None):
        if not str(oid).startswith('demo_'):
            return None
        now=int(time.time())
        with connect() as c:
            if token is not None:
                r=c.execute('SELECT * FROM demo_orders WHERE id=? AND token=?',(oid,token)).fetchone()
            else:
                r=c.execute('SELECT * FROM demo_orders WHERE id=? AND merchant_id=?',(oid,mid)).fetchone()
            if not r:return None
            if r['status']=='PENDING':
                if r['auto_at'] is not None and now>=r['auto_at'] and r['auto_at']<r['expires_at']:
                    c.execute("UPDATE demo_orders SET status='PAID',paid_at=?,utr=? WHERE id=? AND status='PENDING'",(r['auto_at'],'DEMO-'+oid[-12:].upper(),oid))
                elif now>=r['expires_at']:
                    c.execute("UPDATE demo_orders SET status='EXPIRED' WHERE id=? AND status='PENDING'",(oid,))
                r=c.execute('SELECT * FROM demo_orders WHERE id=?',(oid,)).fetchone()
            return dict(r)
    def payload(request,r,with_link=False):
        p={'success':True,'demo':True,'mode':'sandbox','simulated':True,'order_id':r['id'],
           'client_ref':r['client_ref'],'amount':r['amount'],'currency':'INR','status':r['status'],
           'paid':r['status']=='PAID','demo_utr':r['utr'],'expires_at':r['expires_at'],
           'auto_verify_at':r['auto_at'],'paid_at':r['paid_at'],
           'message':'SIMULATION ONLY. No money moved. No live order or payment webhook was created.'}
        if with_link:
            p['payment_url']=str(request.base_url).rstrip('/')+'/demo/pay/'+r['id']+'/'+r['token']
        return p
    @app.get('/playground')
    def playground(request:Request):
        m=current_merchant(request)
        if not m:return RedirectResponse('/login',303)
        import db
        from manual_features import csrf
        keys=[{'id':k['id'],'label':k['label'],'suffix':k['api_key'][-4:]} for k in db.list_api_keys(m['id']) if not k['revoked']]
        settings=db.get_settings(m['id'])
        return render(request,'playground.html',merchant=m,manual_keys=keys,manual_name=settings['display_name'] or m['business_name'],manual_csrf=csrf(request))
    @app.post('/api/v1/demo/order/create')
    async def create(request:Request):
        mid,err=owner(request)
        if err:return err
        try:
            b=await request.json()
            if not isinstance(b,dict):return error('Body must be a JSON object.')
            if isinstance(b.get('amount'),bool):raise ValueError()
            amount=float(b.get('amount'))
            if not math.isfinite(amount) or not 1<=amount<=500000:raise ValueError()
            amount=round(amount,2)
            auto=b.get('auto_verify',True)
            if not isinstance(auto,bool):return error('auto_verify must be true or false.')
        except (ValueError,TypeError,json.JSONDecodeError):
            return error('Provide a valid JSON object and an amount between INR 1 and 500000.')
        now=int(time.time());oid='demo_'+secrets.token_hex(12);token=secrets.token_urlsafe(24)
        with connect() as c:
            # Bound sandbox storage; these are not accounting records.
            c.execute('DELETE FROM demo_orders WHERE created_at < ?',(now-7*86400,))
            c.execute('INSERT INTO demo_orders VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                      (oid,mid,amount,str(b.get('order_id') or '')[:80],'PENDING',token,now,now+900,now+8 if auto else None,None,None))
        return JSONResponse(payload(request,get_order(oid,mid),True),status_code=201)
    @app.api_route('/api/v1/demo/order/status',methods=['GET','POST'])
    async def status(request:Request):
        mid,err=owner(request)
        if err:return err
        oid=request.query_params.get('order_id','')
        if request.method=='POST':
            try:
                b=await request.json()
                if not isinstance(b,dict):return error('Body must be a JSON object.')
                oid=str(b.get('order_id') or oid)
            except (ValueError,TypeError):return error('Body must be valid JSON.')
        r=get_order(oid,mid)
        return JSONResponse(payload(request,r)) if r else error('Demo order not found.',404)
    @app.post('/api/v1/demo/order/verify')
    async def verify(request:Request):
        mid,err=owner(request)
        if err:return err
        try:
            b=await request.json()
            if not isinstance(b,dict):return error('Body must be a JSON object.')
            oid=str(b.get('order_id') or '')
            simulate=b.get('simulate',False)
            if not isinstance(simulate,bool):return error('simulate must be true or false.')
        except (ValueError,TypeError):return error('Body must be valid JSON.')
        r=get_order(oid,mid)
        if not r:return error('Demo order not found.',404)
        # Explicit sandbox simulation only; real order IDs can never reach this write.
        if simulate and r['status']=='PENDING':
            with connect() as c:
                c.execute("UPDATE demo_orders SET status='PAID',paid_at=?,utr=? WHERE id=? AND merchant_id=? AND status='PENDING'",(int(time.time()),'DEMO-'+oid[-12:].upper(),oid,mid))
            r=get_order(oid,mid)
        p=payload(request,r);p['verified']=r['status']=='PAID'
        return JSONResponse(p)
    @app.get('/demo/pay/{oid}/{token}')
    def checkout(request:Request,oid:str,token:str):
        r=get_order(oid,token=token)
        if not r:return error('Demo payment link not found.',404)
        return render(request,'demo_pay.html',demo=r,merchant=None)
    @app.get('/demo/pay/{oid}/{token}/status')
    def checkout_status(request:Request,oid:str,token:str):
        if not rate_ok('demo-public:'+client_ip(request),120,60):return error('Retry shortly.',429)
        r=get_order(oid,token=token)
        return JSONResponse(payload(request,r)) if r else error('Demo payment link not found.',404)
