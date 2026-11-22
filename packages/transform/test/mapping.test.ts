import test from 'node:test';
import assert from 'node:assert/strict';
import {mapRecord,MappingError} from '../src/index.ts';
test('maps nested fields into canonical CRM fields',()=>{
  const result=mapRecord({contact:{email:'customer@example.com'},revenue:'42.5',active:'true'},[
    {from:'contact.email',to:'email',type:'string',required:true},
    {from:'revenue',to:'amount',type:'number',required:true},
    {from:'active',to:'active',type:'boolean'}
  ]);
  assert.deepEqual({...result},{email:'customer@example.com',amount:42.5,active:true});
});
test('optional missing fields are omitted',()=>{
  const result=mapRecord({id:12},[{from:'id',to:'externalId',type:'string'}, {from:'absent',to:'ignored',type:'string'}]);
  assert.deepEqual({...result},{externalId:'12'});
});
test('missing required fields fail closed',()=>assert.throws(
  ()=>mapRecord({},[{from:'id',to:'externalId',type:'string',required:true}]),
  (e:unknown)=>e instanceof MappingError&&e.code==='MISSING_FIELD'));
test('invalid numeric conversion fails instead of silently losing data',()=>assert.throws(
  ()=>mapRecord({amount:'not a number'},[{from:'amount',to:'amount',type:'number'}]),
  (e:unknown)=>e instanceof MappingError&&e.code==='INVALID_VALUE'));
test('prototype pollution mapping targets are rejected',()=>{
  assert.throws(()=>mapRecord({danger:'x'},[{from:'danger',to:'__proto__',type:'raw'}]),
    (e:unknown)=>e instanceof MappingError&&e.code==='INVALID_MAPPING');
  assert.equal(({} as Record<string,unknown>).polluted,undefined);
});
test('prototype paths are rejected',()=>assert.throws(
  ()=>mapRecord({user:{name:'a'}},[{from:'user.constructor',to:'value',type:'raw'}]),
  (e:unknown)=>e instanceof MappingError&&e.code==='INVALID_MAPPING'));
test('does not read inherited properties',()=>{
  const inherited=Object.create({secret:'x'});
  inherited.id=5;
  assert.throws(()=>mapRecord(inherited,[{from:'id',to:'id',type:'number'}]),
    (e:unknown)=>e instanceof MappingError&&e.code==='INVALID_MAPPING');
});
test('duplicate targets are rejected',()=>assert.throws(
  ()=>mapRecord({a:1,b:2},[{from:'a',to:'id',type:'raw'},{from:'b',to:'id',type:'raw'}]),
  (e:unknown)=>e instanceof MappingError&&e.code==='INVALID_MAPPING'));
test('rejects unknown field mapping type',()=>assert.throws(
  ()=>mapRecord({a:1},[{from:'a',to:'id',type:'expression' as 'raw'}]),
  (e:unknown)=>e instanceof MappingError&&e.code==='INVALID_MAPPING'));
