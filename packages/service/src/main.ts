import {parseServiceConfig,createServiceDependencies,startService} from './index.ts';

const config=parseServiceConfig(process.env);
const dependencies=createServiceDependencies(config);
let close:undefined|(()=>Promise<void>);
try {
  const running=await startService(config,dependencies);
  close=running.shutdown;
  // Do not expose full environment or credentials through logs.
  process.stdout.write('Universal Connect service listening on configured loopback port\n');
}catch(error){
  await dependencies.close();
  process.stderr.write('Universal Connect failed to initialize; check configuration and database\n');
  process.exitCode=1;
}
if(close){
  let closing=false;
  const shutdown=()=>{
    if(closing)return;
    closing=true;
    void close!().then(()=>{process.exitCode=0},()=>{
      process.stderr.write('Service shutdown failed\n');process.exitCode=1;
    });
  };
  process.once('SIGTERM',shutdown);
  process.once('SIGINT',shutdown);
}
