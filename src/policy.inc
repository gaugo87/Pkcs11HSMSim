// Policy values absent from old tokens retain the historical simulator defaults.
bool policyAttribute(CK_ATTRIBUTE_TYPE t){
 switch(t){case CKA_SIGN:case CKA_VERIFY:case CKA_WRAP:case CKA_UNWRAP:
 case CKA_DERIVE:case CKA_ENCRYPT:case CKA_DECRYPT:case CKA_EXTRACTABLE:
 case CKA_SENSITIVE:case CKA_PRIVATE:case CKA_MODIFIABLE:case CKA_DESTROYABLE:return true;
 default:return false;}
}
bool permission(const Object& o,CK_ATTRIBUTE_TYPE t){
 auto it=o.policy.find(static_cast<std::uint32_t>(t));if(it!=o.policy.end())return it->second;
 switch(t){
 case CKA_SIGN:case CKA_PRIVATE:return o.cls==CKO_PRIVATE_KEY;
 case CKA_VERIFY:return o.cls==CKO_PUBLIC_KEY;
 case CKA_WRAP:case CKA_UNWRAP:case CKA_DERIVE:case CKA_ENCRYPT:case CKA_DECRYPT:
  return o.cls==CKO_SECRET_KEY&&o.type==CKK_AES;
 case CKA_SENSITIVE:return false;
 case CKA_EXTRACTABLE:case CKA_MODIFIABLE:case CKA_DESTROYABLE:return true;
 default:return false;
 }
}
CK_RV validateTemplate(CK_ATTRIBUTE_PTR a,CK_ULONG n){
 if(!a&&n)return CKR_ARGUMENTS_BAD;
 for(CK_ULONG i=0;i<n;++i){
  for(CK_ULONG j=0;j<i;++j)if(a[i].type==a[j].type)return CKR_TEMPLATE_INCONSISTENT;
  if(!a[i].pValue&&a[i].ulValueLen)return CKR_ATTRIBUTE_VALUE_INVALID;
  if(policyAttribute(a[i].type)||a[i].type==CKA_TOKEN){
   if(!a[i].pValue||a[i].ulValueLen!=sizeof(CK_BBOOL))return CKR_ATTRIBUTE_VALUE_INVALID;
   CK_BBOOL value;std::memcpy(&value,a[i].pValue,sizeof value);
   if(value!=CK_FALSE&&value!=CK_TRUE)return CKR_ATTRIBUTE_VALUE_INVALID;
  }else switch(a[i].type){
   case CKA_CLASS:case CKA_KEY_TYPE:case CKA_VALUE_LEN:case CKA_MODULUS_BITS:case CKA_PARAMETER_SET:
    if(!a[i].pValue||a[i].ulValueLen!=sizeof(CK_ULONG))return CKR_ATTRIBUTE_VALUE_INVALID;break;
   case CKA_LABEL:case CKA_ID:case CKA_EC_PARAMS:case CKA_PUBLIC_EXPONENT:break;
   case CKA_ALWAYS_SENSITIVE:case CKA_NEVER_EXTRACTABLE:case CKA_LOCAL:case CKA_KEY_GEN_MECHANISM:
    return CKR_ATTRIBUTE_READ_ONLY;
   case CKA_VALUE:return CKR_TEMPLATE_INCONSISTENT;
   default:return CKR_ATTRIBUTE_TYPE_INVALID;
  }
 }
 return CKR_OK;
}
bool tokenTemplate(CK_ATTRIBUTE_PTR a,CK_ULONG n,bool fallback=true){
 auto v=attr(a,n,CKA_TOKEN);return v?(*v)[0]!=0:fallback;
}
void setPolicy(Object& o,CK_ATTRIBUTE_PTR a,CK_ULONG n){
 for(CK_ULONG i=0;i<n;++i)if(policyAttribute(a[i].type))
  o.policy[static_cast<std::uint32_t>(a[i].type)]=*static_cast<CK_BBOOL*>(a[i].pValue)!=0;
}
CK_RV creationPolicy(Object& o,CK_SESSION_HANDLE h,CK_ATTRIBUTE_PTR a,CK_ULONG n,bool fallback=true){
 auto rv=validateTemplate(a,n);if(rv)return rv;
 if(attrulong(a,n,CKA_CLASS).value_or(o.cls)!=o.cls||attrulong(a,n,CKA_KEY_TYPE).value_or(o.type)!=o.type)return CKR_TEMPLATE_INCONSISTENT;
 bool token=tokenTemplate(a,n,fallback);
 if(token&&!(session(h)->flags&CKF_RW_SESSION))return CKR_SESSION_READ_ONLY;
 o.owner=token?0:h;setPolicy(o,a,n);if(o.owner)o.path.clear();return CKR_OK;
}
metadata::Records policyRecords(const std::string& path,const Object* replacement=nullptr){
 metadata::Records records;
 for(const auto& [handle,stored]:g.objects)if(!stored.owner&&stored.path==path){
  const auto& o=replacement&&replacement->h==handle?*replacement:stored;
  records.emplace(static_cast<std::uint32_t>(o.cls),metadata::Attributes{o.label,o.id,o.policy});
 }
 return records;
}
static CK_RV CK_CALL SetAttributeValue(CK_SESSION_HANDLE h,CK_OBJECT_HANDLE handle,CK_ATTRIBUTE_PTR a,CK_ULONG n){
 if(!session(h))return CKR_SESSION_HANDLE_INVALID;
 auto* o=object(handle);if(!o)return CKR_OBJECT_HANDLE_INVALID;
 if(!permission(*o,CKA_MODIFIABLE))return CKR_ACTION_PROHIBITED;
 if(!o->owner&&!(session(h)->flags&CKF_RW_SESSION))return CKR_SESSION_READ_ONLY;
 auto rv=validateTemplate(a,n);if(rv)return rv;
 Object changed=*o;
 for(CK_ULONG i=0;i<n;++i){
  auto t=a[i].type;
  if(t==CKA_LABEL||t==CKA_ID){
   auto value=attrstr(a+i,1,t);if(t==CKA_LABEL)changed.label=value;else changed.id=value;
  }else if(policyAttribute(t)){
   bool value=*static_cast<CK_BBOOL*>(a[i].pValue)!=0;
   if((t==CKA_SENSITIVE&&permission(*o,t)&&!value)||(t==CKA_EXTRACTABLE&&!permission(*o,t)&&value))return CKR_ATTRIBUTE_READ_ONLY;
   changed.policy[static_cast<std::uint32_t>(t)]=value;
  }else return CKR_ATTRIBUTE_READ_ONLY;
 }
 if(!changed.owner){try{metadata::create(changed.path,policyRecords(changed.path,&changed),true);}catch(...){return CKR_DEVICE_ERROR;}}
 *o=std::move(changed);return CKR_OK;
}
