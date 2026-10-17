const {defineConfig}=require('@playwright/test');
module.exports=defineConfig({
 testDir:'./tests',testMatch:'live-web.spec.cjs',timeout:60000,workers:1,
 use:{baseURL:'http://127.0.0.1:8765',viewport:{width:1584,height:992},trace:'retain-on-failure'},
 webServer:{command:'python -m cyber_core.web_server --test-mode --home "'+process.env.CYBER_BETA_TEST_HOME+'" --web-root web',url:'http://127.0.0.1:8765/api/health',reuseExistingServer:false},
 reporter:[['list'],['html',{open:'never',outputFolder:'live-playwright-report'}]]
});
