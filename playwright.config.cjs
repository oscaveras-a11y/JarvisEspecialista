const {defineConfig}=require('@playwright/test');
module.exports=defineConfig({
 testDir:'./tests',testMatch:'web.spec.cjs',timeout:20000,
 use:{baseURL:'http://127.0.0.1:4173',viewport:{width:1584,height:992},trace:'retain-on-failure',screenshot:'only-on-failure'},
 webServer:{command:'python -m http.server 4173 --bind 127.0.0.1 --directory web',url:'http://127.0.0.1:4173/',reuseExistingServer:false},
 reporter:[['list'],['html',{open:'never',outputFolder:'playwright-report'}]],workers:1
});