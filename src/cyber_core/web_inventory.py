"""Bounded static HTML inventory. Never execute script or retain field values."""
import codecs
import hashlib
from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit

INPUT_TYPES = {'text','password','hidden','email','number','checkbox','radio','file',
               'submit','button','url','tel','search','date','range','color','reset',
               'datetime-local','month','week','time','image'}
REFERENCES = {'a':'href','area':'href','link':'href','script':'src','iframe':'src','img':'src'}

class _Tags(HTMLParser):
    def __init__(self,owner):
        super().__init__(convert_charrefs=True)
        self.owner=owner

    def handle_starttag(self,tag,attrs):
        self.owner._start(tag,attrs)

    def handle_endtag(self,tag):
        if tag=='form':
            self.owner.current=None

class Inventory:
    def __init__(self,origin,page_path,allowed_paths,*,max_bytes=1048576):
        from cyber_core.web_probe import _origin
        normalized,_,_=_origin(origin)
        if (not isinstance(allowed_paths,list) or not 1<=len(allowed_paths)<=8
                or any(not isinstance(p,str) or not re.fullmatch(r"/[A-Za-z0-9/_~.!$&'()*+,;=:@-]*",p)
                       or len(p)>256 or '//' in p or any(s in ('.','..') for s in p.split('/'))
                       for p in allowed_paths)
                or page_path not in allowed_paths):
            raise ValueError('Invalid inventory scope')
        if type(max_bytes) is not int or not 1<=max_bytes<=1048576:
            raise ValueError('Invalid HTML byte budget')
        self.origin=normalized
        self.page=normalized+page_path
        self.allowed=set(allowed_paths)
        self.limit=max_bytes
        self.seen=0
        self.closed=False
        self.disabled=False
        self.decoder=codecs.getincrementaldecoder('utf-8')('strict')
        self.parser=_Tags(self)
        self.base=None
        self.references=[]
        self.references_seen=0
        self.references_omitted=0
        self.forms=[]
        self.forms_seen=0
        self.current=None
        self.flags=set()
        self.unassociated_fields=0

    def _start(self,tag,attrs):
        attributes={}
        for key,value in attrs:
            if key in attributes:
                self.flags.add('duplicate_attributes')
            else:
                attributes[key]=value
        if tag=='base' and attributes.get('href') is not None:
            href=attributes['href']
            if self.base is None:
                if len(href)<=2048:
                    self.base=href
                else:
                    self.flags.add('base_reference_omitted')
                    self.base=''
            return
        reference=attributes.get(REFERENCES.get(tag))
        if reference is not None:
            self.references_seen+=1
            if len(self.references)>=32 or len(reference)>2048:
                self.references_omitted+=1
                self.flags.add('reference_limit')
            else:
                self.references.append(reference)
        if tag=='form':
            self.forms_seen+=1
            if self.current is not None:
                self.flags.add('nested_forms_unsupported')
                self.current=None
                return
            if len(self.forms)>=2:
                self.flags.add('form_limit')
                return
            method=(attributes.get('method') or 'GET').strip().upper()
            if method not in ('GET','POST','DIALOG'):
                self.flags.add('invalid_form_method')
                method='GET'
            action=attributes.get('action')
            if action is not None and len(action)>2048:
                action=None
                self.flags.add('form_action_omitted')
            form={'method':method,'_action':action,'fields':[],'fields_seen':0,'fields_omitted':0,
                  'csrf_related_name_observed':False}
            self.forms.append(form)
            self.current=form
            return
        if tag not in ('input','textarea','select','button'):
            return
        if 'form' in attributes:
            self.flags.add('form_attribute_associations_unsupported')
            return
        if self.current is None:
            self.unassociated_fields+=1
            return
        form=self.current
        form['fields_seen']+=1
        if len(form['fields'])>=8:
            form['fields_omitted']+=1
            self.flags.add('field_limit')
            return
        kind=(attributes.get('type') or 'text').strip().lower() if tag=='input' else tag
        if tag=='input' and kind not in INPUT_TYPES:
            kind='other'
        name=attributes.get('name') or ''
        field={'kind':kind,'name_sha256':None}
        if len(name)>128:
            self.flags.add('field_name_omitted')
        elif name:
            field['name_sha256']=hashlib.sha256(name.encode('utf-8')).hexdigest()
            if 'csrf' in name.lower() or 'xsrf' in name.lower():
                form['csrf_related_name_observed']=True
        form['fields'].append(field)

    def feed(self,block):
        if self.closed or not isinstance(block,bytes):
            raise ValueError('Invalid or closed inventory stream')
        self.seen+=len(block)
        if self.seen>self.limit:
            raise ValueError('HTML input byte limit exceeded')
        if self.disabled:
            return
        try:
            self.parser.feed(self.decoder.decode(block))
        except (UnicodeError,ValueError):
            self.disabled=True
            self.flags.add('unsupported_or_invalid_utf8')

    def _resolve(self,value,base):
        try:
            absolute=urljoin(base,value.strip())
            target=urlsplit(absolute)
            expected=urlsplit(self.origin)
            if (target.scheme!='https' or target.username is not None or target.password is not None
                    or target.hostname!=expected.hostname
                    or (443 if target.port is None else target.port)!=(443 if expected.port is None else expected.port)
                    or any(ord(c)<32 or ord(c)>=127 for c in target.path)
                    or target.path not in self.allowed):
                return None
            return {'path':target.path,'query_removed':bool(target.query or target.fragment)}
        except (ValueError,TypeError):
            return None

    def finish(self,*,body_complete=True):
        if self.closed:
            raise ValueError('Inventory already closed')
        self.closed=True
        if not self.disabled:
            try:
                self.parser.feed(self.decoder.decode(b'',final=True))
                if self.parser.rawdata.lstrip().startswith('<'):
                    self.flags.add('unfinished_markup')
                self.parser.close()
            except (UnicodeError,ValueError):
                self.flags.add('unsupported_or_invalid_utf8')
        if not body_complete:
            self.flags.add('body_incomplete')
        base=urljoin(self.page,self.base) if self.base is not None else self.page
        routes={}
        out_of_scope=0
        for reference in self.references:
            resolved=self._resolve(reference,base)
            if resolved is None:
                out_of_scope+=1
            else:
                path=resolved['path']
                if path in routes:
                    routes[path]['query_removed'] |= resolved['query_removed']
                else:
                    routes[path]=resolved
        forms=[]
        for source in self.forms:
            form={key:value for key,value in source.items() if not key.startswith('_')}
            # Missing/empty action targets the document, independently of base.
            action=source['_action']
            resolved=self._resolve(self.page,self.page) if not action else self._resolve(action,base)
            form['action_in_scope']=resolved is not None
            form['action_path']=None if resolved is None else resolved['path']
            form['action_query_removed']=False if resolved is None else resolved['query_removed']
            forms.append(form)
        return {'version':'html-inventory-1','status':'partial' if self.flags else 'completed',
                'routes':list(routes.values()),'forms':forms,'forms_seen':self.forms_seen,
                'forms_omitted':max(0,self.forms_seen-len(forms)),
                'references_seen':self.references_seen,'references_omitted':self.references_omitted,
                'references_out_of_scope':out_of_scope,'unassociated_fields':self.unassociated_fields,
                'quality_flags':sorted(self.flags),'interpretation':'Static HTML observations, not vulnerability verdicts'}
