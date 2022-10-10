const fritz = require('fritzapi');
const options = {
    url: 'https://172.16.101.111',
    strictSSL: false  }

fritz.getSessionID("root", "bisdn$2022", options).then(function(sid){
      console.log(sid);
      fritz.getSwitchList(sid, options).then(function(ains){
        fritz.setSwitchOn(sid, ains, options);
      });
});
