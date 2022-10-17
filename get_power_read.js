const fritz = require('fritzapi');
const options = {
    url: 'https://172.16.102.17',
    strictSSL: false  }

fritz.getSessionID("root", "bisdn$2022", options).then(function(sid){
      console.log(sid);
      fritz.getSwitchList(sid, options).then(function(ains){
        fritz.getSwitchPower(sid, ains, options).then(function(power){
            console.log(power);
      });
      });
});
