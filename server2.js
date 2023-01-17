const express = require('express');
const cookieParser = require("cookie-parser");
const sessions = require('express-session');
var app = express();

var md5 = require("md5");
var fs = require('fs');
var http = require('http')
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const key = "NcQfTjWnZr4u7x!A%D*G-KaPdSgUkXp2";
const iv = "COUNT-TO-1234567";

bodyParser = require('body-parser');

var accounts = {};
var ctfend=0;
const fivedays = 1000 * 60 * 60 * 24 * 5;


//session middleware
app.use(sessions({
    secret: "PatrykIsSuperCoolAndGoodAtCodingWow$1",
    saveUninitialized:true,
    cookie: { maxAge: fivedays },
    resave: false
}));


app.use(cookieParser());

var session;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('templates'));

app.set('view engine', "ejs");
let db = new sqlite3.Database('protected/data.db', sqlite3.OPEN_READWRITE, (err) => {
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
  var stmt = "select * from users where email=(?);";
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



async function inqueue(){

  var stmt2 = "SELECT name, description, author, downloads FROM challs";

  var inq; var arr=[]
  await new Promise((resolve) => {
    db.all(stmt2, (err, row) => {
      inq=row;
      resolve();
    });
  });
  inq.sort(function(first, second) {  return  Number(first.author.split(":")[0]) - Number(second.author.split(":")[0]); });

  var date = new Date;

  inq.forEach(first => {

    if (Number(first.author.split(":")[0]) * 60 + Number(first.author.split(":")[1]) - date.getHours() * 60 - date.getMinutes() > 0){
      first["status"] = "badge bg-success status";
      first["message"] = "Upcoming";
    }
    else{
      if (Number(first.downloads.split(":")[0]) * 60 + Number(first.downloads.split(":")[1]) - date.getHours() * 60 - date.getMinutes() > 0){
        first["status"] = "badge bg-warning status";
        first["message"] = "Current";
      }
      else{
        first["status"] = "badge bg-danger status";
        first["message"] = "Completed";
      }
    }
    if (Number(first.author.split(":")[0]) > 12){
      first.author = "" + ((Number(first.author.split(":")[0])-12)) + ":" + first.author.split(":")[1] + " PM"
    }
    else if (Number(first.author.split(":")[0]) == 12){
      first.author = first.author + " PM";
    }
    else{
      first.author = first.author + " AM";
    }

    if (Number(first.downloads.split(":")[0]) > 12){
      first.downloads = "" + ((Number(first.downloads.split(":")[0])-12)) + ":" + first.downloads.split(":")[1] + " PM"
    }
    else if (Number(first.downloads.split(":")[0]) == 12){
      first.downloads = first.downloads + " PM";
    }
    else{
      first.downloads = first.downloads + " AM";
    }
  });

  return inq;
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
    if (info["tStart"].split(":").length != 2 || info["tEnd"].split(":").length != 2){
      return;
    }
    else{
      if (!(!isNaN(parseInt(info["tStart"].split(":")[0])) && !isNaN(parseInt(info["tStart"].split(":")[1])) && !isNaN(parseInt(info["tEnd"].split(":")[0])) && !isNaN(parseInt(info["tEnd"].split(":")[0])))){
        return;
      }
    }
    await new Promise((resolve) => {
      
        db.get(stmt1, [info["cname"],info["cdesc"],info["tStart"],info["tEnd"],info["cat"],info["flag"],info["base"]], (err, row) => {
      resolve();
    });
        
      });
    await new Promise((resolve) => {
        var stmt5="create table `"+info["cname"]+"` (team VARCHAR(255), time integer)";
        db.run(stmt5);
        resolve();
  
      });
    
  }

  if (info["delete"]!=undefined){
    await new Promise((resolve) => {
      
        db.get(stmt4, [info["delete"]], (err, row) => {
      resolve();

    });
        
      });
    await new Promise((resolve) => {
      
        var stmt6="drop table `"+info["delete"]+"`";
        db.run(stmt6);
        resolve();
      });
    
  }
}

app.get('/login', (req, res) => {
  session=req.session;
  if (session.userid){
    res.redirect('/');
  }
  else{
    res.sendFile(__dirname + '/public' +'/login.html');
  }
});

app.post('/login', (req, res) => {
  check2(req.body.email,req.body.password).then(result => {
    if (result===1){
      res.sendFile(__dirname + '/public' +'/error1.html');
    }
    else{

      session=req.session;
      session.userid=req.body.email;
  
      res.redirect('/');
    }
  });
});

app.get('/register', (req, res) => {
  session=req.session;
  if (session.userid){
    res.redirect('/');
  }
  else{
    res.sendFile(__dirname + '/public' +'/register.html');
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
        session.userid=req.body.email;
        db.run(stmt3);
        stmt.run(req.body.username,md5(req.body.password),req.body.email,req.body.hs==="Highschool",encrypt(req.body.username)["encryptedData"],req.body.ref);
        // if (req.body.ref.length!==0){
        //   stmt2.run(req.body.ref);
        // }
        
        res.redirect('/');
      }
  });
});



app.use(function(req, res, next) {

    if(!req.session.userid) {       
        res.redirect('/login');
    } else {
        next();
    }
});

app.get('/', (req, res) => {

  session=req.session;
  if (session.userid){
    inqueue(session.userid).then(result => {

        res.render('index', {res: result});
      });
  }
  else{
    res.redirect('/login');
  }
  
});


app.use(express.static('public'));

app.get('/signout',(req,res) => {
    req.session.destroy();
    res.redirect('/');
});
app.get('/admin', (req, res) => {
  session=req.session;
  if (session.userid=="danielmathew2006@gmail.com" || session.userid == "givinghopecorps@gmail.com"){
    inqueue(session.userid).then(result => {

        res.render('admin', {res: result});
      });
    
  }
  else{
    res.redirect('/');
  }
});

app.post('/admin',(req,res) => {
    session=req.session;
    if (session.userid=="danielmathew2006@gmail.com" || session.userid == "givinghopecorps@gmail.com"){

      dowork(req.body).then(result => {
        inqueue(session.userid).then(result => {
        res.render('admin', {res: result});
      });
      });
      
    }
    else{
      res.redirect('/');
    }
});

app.get('/speechtotext', (req, res) => {
  session=req.session;
  if (session.userid){
    res.sendFile(__dirname + '/public' +'/speechtotext.html');
  }
  else{
    res.sendFile(__dirname + '/public' +'/login.html');
  }
});

app.get('/registeruser', (req, res) => {
  session=req.session;
  if(session.userid){
    res.sendFile(__dirname + '/public' + '/index2.html');
  }
  else{
    res.sendFile(__dirname + '/public' +'/templates/registeruser.html');
  }
});

app.post('/registeruser', (req, res) => {
  session=req.session;
  if(session.userid){
    res.sendFile(__dirname + '/public' + '/index2.html');
  }
  else{
    var stmt = db.prepare("insert into users values (?, ?, ?, ?);");
    session=req.session;
    session.userid = req.body.username;
    stmt.run(req.body.username, md5(req.body.password), req.body.email, req.body.hs==="Highschool");
    res.sendFile(__dirname + '/public' + '/index3.html');
  }
});



app.get('/leaderboard', (req, res) => {
  session=req.session;

  normlead().then(result => {

      if (session.userid){
        res.render('leaderboard',{res:result[0], len: result[0].length, high:result[1], type: "Main"});
      }
      else{
        res.redirect('/');
      }
  });
  

});

app.post('/leaderboard', (req, res) => {
  session=req.session;
 
  if (session.userid){
    var type = Object.keys(req.body)[0];

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
    res.redirect('/');
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
    res.redirect('/');
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
    res.redirect('/');
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
    res.redirect('/');
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
        
          res.render('challenges',{challs:result[0], you: result[1], re: r});
        });
      });
    });
  }
  else{
    res.redirect('/');
  }

});


app.use((error, req, res, next) => {
 console.error(error.stack);
 res.status(500).send("Something Broke!");
})

const host = 'localhost';
const port = 8000;

const requestListener = function (req, res) {};

const server = http.createServer(app);
server.listen(port, host, () => {
    console.log(`Server is running on http://${host}:${port}`);
});