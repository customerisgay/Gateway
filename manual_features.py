"""Session-scoped manual links, profile names, and pending-payment cancellation."""
import hashlib,hmac,json,math,time,os
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import Request,Form
from fastapi.responses import JSONResponse,RedirectResponse
_NS={}
def token(value):
    key=os.environ.get('FAMGATE_VAULT_KEY','').strip().encode()
    if not key:
        _NS['security']._get_fernet()
        key=Path(_NS['security'].KEY_PATH).read_bytes()
    return hmac.new(key,('manual-v1:'+value).encode(),hashlib.sha256).hexdigest()
def csrf(request):return token('session:'+request.cookies.get('famgate_session',''))
def allowed(request):
    origin=request.headers.get('origin','')
    return bool(origin) and urlsplit(origin).netloc==urlsplit(str(request.base_url)).netloc and request.headers.get('sec-fetch-site','same-origin')!='cross-site'
def register(ns):
    global _NS
    _NS=ns;app=ns['app'];db=ns['db'];render=ns['render'];current=ns['current_merchant']
    with db.connect() as c:c.execute('CREATE TABLE IF NOT EXISTS order_display_names (order_id TEXT PRIMARY KEY REFERENCES orders(id), merchant_name TEXT NOT NULL)')
    def error(message,code=400):return JSONResponse({'success':False,'error':message},status_code=code)
    @app.post('/app/manual/order/create')
    async def create(request:Request):
        m=current(request)
        if not m:return error('Please log in.',401)
        if not allowed(request) or not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf(request)):return error('Refresh the page and try again.',403)
        if not ns['rate_ok']('manual:'+str(m['id']),30,60):return error('Too many requests. Try again shortly.',429)
        try:
            body=await request.json();kid=int(body.get('key_id'));amount=float(body.get('amount'));name=str(body.get('merchant_name') or '').strip()
            if not math.isfinite(amount) or amount<1 or amount>500000:raise ValueError()
            expiry=int(body.get('expiry_minutes',15))
            if not 1<=expiry<=60 or len(name)>80 or any(ord(x)<32 for x in name):raise ValueError()
        except (ValueError,TypeError,AttributeError):return error('Check the amount, key, merchant name and expiry.')
        with db.connect() as c:key=c.execute('SELECT api_key FROM api_keys WHERE id=? AND merchant_id=? AND revoked=0',(kid,m['id'])).fetchone()
        if not key:return error('Select an active API key from your account.',403)
        settings=db.get_settings(m['id']);name=name or settings['display_name'] or m['business_name']
        scope=dict(request.scope);scope['headers']=[(k,v) for k,v in request.scope['headers'] if k.lower() not in (b'x-api-key',b'authorization')]+[(b'x-api-key',key['api_key'].encode())]
        scope['state']=dict(scope.get('state',{}),manual_name=name,manual_source='manual_link')
        internal=Request(scope);internal._body=json.dumps(dict(body,amount=amount,expiry_minutes=expiry)).encode()
        return await ns['api_order_create'](internal)
    @app.get('/profile')
    def profile(request:Request):
        m=current(request)
        if not m:return RedirectResponse('/login',303)
        return render(request,'profile.html',merchant=m,settings=db.get_settings(m['id']),profile_csrf=csrf(request))
    @app.post('/profile')
    def save_profile(request:Request,merchant_name:str=Form(...),csrf_token:str=Form(...)):
        m=current(request)
        if not m:return RedirectResponse('/login',303)
        if not allowed(request) or not hmac.compare_digest(csrf_token,csrf(request)):return error('Refresh the page and try again.',403)
        name=merchant_name.strip()
        if not name or len(name)>80 or any(ord(x)<32 for x in name):return ns['flash_redirect']('/profile',err='Enter a merchant name of 1–80 characters.')
        with db.connect() as c:
            c.execute('UPDATE merchants SET business_name=? WHERE id=?',(name,m['id']))
            c.execute('UPDATE merchant_settings SET display_name=?,updated_at=? WHERE merchant_id=?',(name,int(time.time()),m['id']))
        return ns['flash_redirect']('/profile',ok='Profile updated.')
    def cancel_order(oid):
        with db.connect() as c:
            c.execute("UPDATE orders SET status='CANCELLED' WHERE id=? AND status='PENDING' AND expires_at>?",(oid,int(time.time())))
        o=db.get_order(oid)
        return o
    @app.post('/pay/{order_id}/cancel')
    def cancel_checkout(request:Request,order_id:str,cancel_token:str=Form(...)):
        o=db.get_order(order_id)
        if not o:return error('Payment not found.',404)
        if not allowed(request) or not hmac.compare_digest(cancel_token,token('cancel:'+order_id)):return error('Refresh the checkout and try again.',403)
        if not ns['rate_ok']('cancel:'+ns['client_ip'](request),30,60):return error('Try again shortly.',429)
        o=cancel_order(order_id)
        return ns['flash_redirect']('/pay/'+order_id,ok='Payment cancelled.' if o['status']=='CANCELLED' else '',err='' if o['status']=='CANCELLED' else 'This payment can no longer be cancelled.')
    @app.post('/orders/{order_id}/cancel')
    def cancel_merchant(request:Request,order_id:str,csrf_token:str=Form(...)):
        m=current(request)
        if not m:return RedirectResponse('/login',303)
        if not allowed(request) or not hmac.compare_digest(csrf_token,csrf(request)):return error('Refresh the page and try again.',403)
        if not db.get_order_by_merchant(order_id,m['id']):return error('Payment not found.',404)
        o=cancel_order(order_id)
        return ns['flash_redirect']('/orders',ok='Payment cancelled.' if o['status']=='CANCELLED' else '',err='' if o['status']=='CANCELLED' else 'This payment can no longer be cancelled.')
    ns['manual_csrf']=csrf;ns['cancel_token_for']=lambda oid:token('cancel:'+oid)
