const express = require('express');
const cookieParser = require("cookie-parser");
const sessions = require('express-session');
var app = express();

var md5 = require("md5");
var fs = require('fs');
const http = require('http');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const key = "DefyGGDoesNotCareAboutSecureIV12";
const iv = "COUNT-TO-1234567";

bodyParser = require('body-parser');

var accounts = {};
var ctfend=0;
const fivedays = 1000 * 60 * 60 * 24 * 5;

const privateKey = fs.readFileSync('/etc/letsencrypt/live/ctf.pbjar.net/privkey.pem', 'utf8');
const certificate = fs.readFileSync('/etc/letsencrypt/live/ctf.pbjar.net/cert.pem', 'utf8');
const ca = fs.readFileSync('/etc/letsencrypt/live/ctf.pbjar.net/chain.pem', 'utf8');

const credentials = {
  key: privateKey,
  cert: certificate,
  ca: ca
};

//session middleware
app.use(sessions({
    secret: "thisissecretandDefyGGisverycoolajdhbaowihdowaijhd",
    saveUninitialized:true,
    cookie: { maxAge: fivedays },
    resave: false
}));


app.use(cookieParser());

var session;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.set('view engine', "ejs");
let db = new sqlite3.Database('protected/IknowthisisreallyvulnerablebutIdontknowanyotherwaytoprotectourdbthatdoesnottakeanhourtomake.db', sqlite3.OPEN_READWRITE, (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to best database ever');
});

function encrypt(text) {
 let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
 let encrypted = cipher.update(text);
 encrypted = Buffer.concat([encrypted, cipher.final()]);
 return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text) {
 let iv = Buffer.from(text.iv, 'hex');
 let encryptedText = Buffer.from(text.encryptedData, 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
 let decrypted = decipher.update(encryptedText);
 decrypted = Buffer.concat([decrypted, decipher.final()]);
 return decrypted.toString();
}

async function check(user, email){
  var stmt = "select count(*) from users where un=(?);";
  var stmt2 = "select count(*) from users where email=(?);";
  let val=0;
  await new Promise((resolve) => {
    
    db.get(stmt, [user], (err, row) => {
      console.log(row);
      if (row["count(*)"]!==0){
        val=1;
      }
      resolve();
    });
  });

  await new Promise((resolve) => {
    db.get(stmt2, [email], (err, row) => {
      if (row["count(*)"]!==0){
        val=1;
      }
      resolve();
    });
  });
  return val;
}

async function check2(user, pwd){
  var stmt = "select * from users where un=(?);";
  let val=0;
  await new Promise((resolve) => {
    db.get(stmt, [user], (err, row) => {
      if (row===undefined || row["pass"]!==md5(pwd)){
        val=1;
      }
      resolve();
    });
  });
  return val;
}

async function gettoken(user){
  var stmt = "select * from users where un=(?);";
  let val="";
  await new Promise((resolve) => {
    db.get(stmt, [user], (err, row) => {
      val=row["token"];
      resolve();
    });
  });
  return val;
}
async function getreferals(user){
  var stmt = "select * from users where un=(?);";
  let val="";
  await new Promise((resolve) => {
    db.get(stmt, [user], (err, row) => {
      val=row["verify"];
      resolve();
    });
  });
  return val;
}
function CTFCCCFormula(pts,cnt) {
  var base = pts * 0.2;
  var res = base + ((pts - base) / Math.pow(1 + Math.max(0,cnt) / 100.92201,1.206069));
  return Math.max(1,Math.round(res));
}
async function getreflead(){
  var stmt = "SELECT * FROM users order by verify desc;";
  var val; var arr=[];
  var high=[]
  await new Promise((resolve) => {
    db.all(stmt, (err, row) => {
      val=row;
      resolve();
    });
  });

  await new Promise((resolve) => {
    for (var i=0;i<val.length;i++){
      arr.push({name: val[i]["un"],points: val[i]["verify"]});
      high.push(val[i]["highschool"]);
    } 
    resolve();
  });
  
  return [arr,high];
}

async function normlead(){
  var stmt = "SELECT * FROM users;";
  const map = new Map();
  var stmt3 = "SELECT * FROM challs WHERE name = ? and rank=3;";
  var users; 
  await new Promise((resolve) => {
    db.all(stmt, (err, row) => {
      users=row;
      resolve();
    });
  });
  var scoreboard=[];
  for (var i=0;i<users.length;i++){
    map.set(users[i]["un"],users[i]["highschool"]);
    const challs = new Set(); var val; 
    var score=0;
    var latesttime=0;
    await new Promise((resolve) => {
      var stmt2 = "SELECT * FROM `" + md5(users[i]["un"])+"`;";
      db.all(stmt2, (err, row) => {
        val=row;
        resolve();
      });
    });
 
    for (var j=0; j<val.length;j++){
      console.log(val[j]["chall_name"]);

      await new Promise((resolve) => {
        db.get(stmt3, [val[j]["chall_name"]], (err, row) => {
          if (row===undefined){
            resolve();

          }
          else{
            score+=CTFCCCFormula(row["base"],row["solves"]);
            latesttime=Math.max(latesttime,val[j]["time"]);
            resolve();
          }
          
        });
      });

      
    }
    scoreboard.push({name: users[i]["un"],points: score, lt: latesttime, high: users[i]["highschool"]});


    
  } 
  scoreboard.sort(function (x, y) {
      var n =  y.points-x.points;
      if (n !== 0) {
          return n;
      }

      return  y.lt-x.lt;
  })
  var high=[]

  for (var i=0;i<scoreboard.length;i++){

    high.push(map.get(scoreboard[i].name));
  }


  
  return [scoreboard,high];
}


function userIsAllowed(callback) {
  callback(false);
};

app.get('/leaderboard', (req, res) => {
  session=req.session;

  normlead().then(result => {

      if (session.userid){
        res.render('leaderboard',{res:result[0], len: result[0].length, high:result[1], type: "Main"});
      }
      else{
        res.sendFile(__dirname + '/public' +'/index.html');
      }
  });
  

});

app.post('/leaderboard', (req, res) => {
  session=req.session;
 
  if (session.userid){
    var type = Object.keys(req.body)[0];
    console.log(type);
    if (type==="Main"){
      getreflead().then(result => {
 
        res.render('leaderboard',{res:result[0], len: result[0].length, high:result[1], type: "Referral"});
      });
    }
    else{
      normlead().then(result => {

        res.render('leaderboard',{res:result[0], len: result[0].length, high:result[1], type: "Main"});
      });
    }
    
  }
  else{
    res.sendFile(__dirname + '/public' +'/index.html');
  }
  
  

});

app.get('/', (req, res) => {
  console.log("aaa");
  session=req.session;
  if (session.userid){
    res.sendFile(__dirname + '/public' +'/index2.html');
  }
  else{
    res.sendFile(__dirname + '/public' +'/index.html');
  }
  
});

app.get('/protected/*', function(req, res, next) {
  userIsAllowed(function(allowed) {
    if (allowed) {
      next(); // call the next handler, which in this case is express.static
    } else {
      res.end('You are not allowed!');
    }
  });
});

app.get('/login', (req, res) => {
  session=req.session;
  if (session.userid){
    res.sendFile(__dirname + '/public' +'/index2.html');
  }
  else{
    res.sendFile(__dirname + '/public' +'/templates/login.html');
  }
});

app.post('/login', (req, res) => {
  check2(req.body.uname,req.body.pwd).then(result => {
    if (result===1){
      res.sendFile(__dirname + '/public' +'/error1.html');
    }
    else{
      session=req.session;
      session.userid=req.body.uname;
      res.sendFile(__dirname + '/public' +'/index2.html');
    }
  });
});

app.get('/register', (req, res) => {
  session=req.session;
  if (session.userid){
    res.sendFile(__dirname + '/public' +'/index2.html');
  }
  else{
    res.sendFile(__dirname + '/public' +'/templates/register.html');
  }
});


app.post('/register', (req, res) => {
  check(req.body.username,req.body.email).then(result => {
      if (result===1){
        res.sendFile(__dirname + '/public' +'/error2.html');
      }
      else{
        var stmt = db.prepare("insert into users values (?, ?, ?, 1,?,?,?);");
        var stmt2=db.prepare("update users set verify=verify+1 where token=?;");
        var stmt3="CREATE table `" +  md5(req.body.username) + "` (chall_name varchar(255), chall_id Varchar(255), time integer);";

        session=req.session;
        session.userid=req.body.username;
        db.run(stmt3);
        stmt.run(req.body.username,md5(req.body.password),req.body.email,req.body.hs==="Highschool",encrypt(req.body.username)["encryptedData"],req.body.ref);
        if (req.body.ref.length!==0){
          stmt2.run(req.body.ref);
        }
        
        res.sendFile(__dirname + '/public' +'/index2.html');
      }
  });
});

app.get('/logout',(req,res) => {
    req.session.destroy();
    res.redirect('/');
});


async function inqueue(){

  var stmt2 = "SELECT name FROM challs WHERE rank = 3;";
  var stmt3 = "SELECT name FROM challs WHERE rank = 0;";
  var inq, onq; var arr=[[],[]]
  await new Promise((resolve) => {
    db.all(stmt3, (err, row) => {
      inq=row;
      resolve();
    });
  });
  await new Promise((resolve) => {
    db.all(stmt2, (err, row) => {
      onq=row;
      resolve();
    });
  });

  await new Promise((resolve) => {
    for (var i=0;i<inq.length;i++){
      arr[0].push(inq[i]["name"]);
    }
    for (var i=0;i<onq.length;i++){
      arr[1].push(onq[i]["name"]);
    }
    resolve();
  });
  return arr;
}

async function dowork(info){
  var stmt3 = "update challs set rank=3;";
  var stmt2 ="update users set pass = ? where un = ? and email = ?";
  var stmt55 ="update challs set name = ?, description = ?, author = ?, downloads=?, type = ?, flag = ?, base = ? where name = ?";
  var stmt21 ="select count(*) from users where un = ? and email = ?";
  var stmt4="delete from challs where name=?";
  var stmt1="insert into challs values (?, ?, ?, 0, ?, ?, ?, 0, ?)";
  var test = "select * from challs;";

  if (info["cname"]!=undefined){
    await new Promise((resolve) => {
      
        db.get(stmt1, [info["cname"],info["cdesc"],info["author"],info["zip"],info["cat"],info["flag"],info["base"]], (err, row) => {
      resolve();
    });
        
      });
    await new Promise((resolve) => {
        var stmt5="create table `"+info["cname"]+"` (team VARCHAR(255), time integer)";
        db.run(stmt5);
        resolve();
  
      });
    
  }
  if (info["cnameu"]!=undefined){
    await new Promise((resolve) => {

        var stmt55 ="update challs set name = ?, description = ?, author = ?, downloads=?, type = ?, flag = ?, base = ? where name = ?";

        db.get(stmt55, [info["cnameuu"],info["cdesc"],info["author"],info["zip"],info["cat"],info["flag"],info["base"],info["cnameu"]], (err, row) => {
 
          resolve();
        });
  
        
      });
    
  }
  if (info["cnamed"]!=undefined){
    await new Promise((resolve) => {
      
        db.get(stmt4, [info["cnamed"]], (err, row) => {
      resolve();

    });
        
      });
    await new Promise((resolve) => {
      
        var stmt6="drop table `"+info["cnamed"]+"`";
        db.run(stmt6);
        resolve();
      });
    
  }
  if (info["teame"]!=undefined){
    var val;
    await new Promise((resolve) => {
      
        db.get(stmt21, [info["team"],info["teame"]], (err, row) => {
          val=row["count(*)"];
          resolve();
        });
        
      });
 
    await new Promise((resolve) => {
      
        if (val==1){
          db.get(stmt2, [info["pass"],info["team"],info["teame"]], (err, row) => {

            resolve();
          });
        }
        
      });

  }
  if (info["release"]!=undefined){
    if (info["release"]==="yes"){
      await new Promise((resolve) => {
        db.run(stmt3);
        resolve();
      });
    }
  }
  if (info["stop"]!=undefined){
    if (info["stop"]==="yes"){
      ctfend=1;
    }
  }
}


app.get('/adminpanel',(req,res) => {
    session=req.session;
    if (session.userid=="PeanutButter.jar Orgs"){
      inqueue(session.userid).then(result => {
 
        res.render('adminpanel', {res: result});
      });
      
    }
    else{
      res.redirect('/');
    }
});

app.post('/adminpanel',(req,res) => {
    session=req.session;
    if (session.userid=="PeanutButter.jar Orgs"){
      dowork(req.body).then(result => {
        res.redirect('/adminpanel');
      });
      
    }
    else{
      res.redirect('/');
    }
});


async function teamstuff(name){
  var stmt = "SELECT * FROM  `" + md5(name) +"`";
  var val; var arr=[];
  var high=[]
  await new Promise((resolve) => {
    db.all(stmt, (err, row) => {
      val=row;
      resolve();
    });
  });

  await new Promise((resolve) => {
    for (var i=0;i<val.length;i++){
      arr.push({name: val[i]["chall_name"],points: val[i]["time"]});

    } 
    resolve();
  });
  
  return arr;
}

app.get('/team', (req, res) => {
  session=req.session;
  if (session.userid){
    getreferals(session.userid).then(result => {
        teamstuff(session.userid).then(result2 => {
         
          res.render('team',{name:session.userid,token:encrypt(session.userid)["encryptedData"],refers:result, res:result2});
        });
      
    });
  }
  else{
    res.sendFile(__dirname + '/public' +'/index.html');
  }

});

app.post('/team', (req, res) => {
  session=req.session;
  if (session.userid){
    var a = Buffer.from(req.body["teamn"], 'base64').toString('utf-8');

    getreferals(a).then(result => {
      teamstuff(a).then(result2 => {
          res.render('team',{name:a,token:encrypt(a)["encryptedData"],refers:result, res:result2});
        });
    });
  }
  else{
    res.sendFile(__dirname + '/public' +'/index.html');
  }

});
async function getchalllead(name){
  var stmt = "SELECT * FROM challs where rank = 3 order by solves desc;";

  var stmt2 = "SELECT * FROM `" + md5(name)+"`";
  var val;var val2;  var arr=[];
  const v2=[];
  await new Promise((resolve) => {
    db.all(stmt, (err, row) => {
      val=row;
      resolve();
    });
  });
  if (ctfend===1){
    val=[];
  }
  await new Promise((resolve) => {
    db.all(stmt2, (err, row) => {
      val2=row;
      resolve();
    });
  });
  
  await new Promise((resolve) => {
    for (var i=0;i<val.length;i++){
      arr.push({"name":val[i]["name"],"description":val[i]["description"],"author":val[i]["author"],"solves":val[i]["solves"],"type":val[i]["type"],"downloads":val[i]["downloads"],"base":val[i]["base"]});
    } 
    resolve();
  });
  await new Promise((resolve) => {
    for (var i=0;i<val2.length;i++){
      v2.push(val2[i]["chall_name"]);
    } 
    resolve();
  });

  return [arr,v2];
}

async function confirm(chall, flag, user){
  var stmt = "select * from challs where name=(?);";
  var stmt2 = "select count(*) from `" + md5(user) + "` where chall_name=(?);";
  let val=0;

  await new Promise((resolve) => {
    db.get(stmt, [chall], (err, row) => {
      if (row["flag"]===flag){
        val=1;
      }
      resolve();
    });
  });
  await new Promise((resolve) => {
    db.get(stmt2, [chall], (err, row) => {
      if (row["count(*)"]!==0){
        val=2;
      }
      resolve();
    });
  });

  await new Promise((resolve) => {
    if (ctfend===1){
      val=3;
    }
    resolve();
  });
  return val;

}

async function add(chall, user, r){
  var stmt = db.prepare("insert into `"+md5(user)+"` values (?, ?, ?);");
  var stmt2 = db.prepare("update challs set solves = solves + 1 where name = (?)");
  if (r==1){
    await new Promise((resolve) => {
      stmt.run(chall,md5(chall),Date.now());
      resolve();
    });
    await new Promise((resolve) => {
      stmt2.run(chall);
      resolve();
    });
  }
}


app.get('/challenges', (req, res) => {
  session=req.session;
  if (session.userid){
    getchalllead(session.userid).then(result => {

      res.render('challenges',{challs:result[0], you: result[1], re:-1});
    });
  }
  else{
    res.sendFile(__dirname + '/public' +'/index.html');
  }

});
app.post('/challenges', (req, res) => {
  session=req.session;
  if (session.userid){
    var cname = Object.keys(req.body)[0];
    var flag = req.body[cname];
    confirm(cname,flag,session.userid).then(r => {
      add(cname,session.userid,r).then(result => {
        getchalllead(session.userid).then(result => {
          console.log(r);
          res.render('challenges',{challs:result[0], you: result[1], re: r});
        });
      });
    });
  }
  else{
    res.sendFile(__dirname + '/public' +'/index.html');
  }

});


app.use((error, req, res, next) => {
 console.error(error.stack);
 res.status(500).send("Something Broke!");
})

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(443, () => {
  console.log('HTTPS Server running on port 443');
});


http.createServer(function (req, res) {
    res.writeHead(301, { "Location": "https://" + req.headers['host'] + req.url });
    res.end();
}).listen(80);
