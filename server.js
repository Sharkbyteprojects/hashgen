const express = require("express");
const mog = require("morgan");
const compression = require("compression");
const { Observable } = require("rxjs");
const helmet = require("helmet");
const session = require("express-session");
const hash = require("shark-hashlib");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const app = express();
const rel=require("reloadsh.js");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());
app.use(compression());
const csrfProtection = csrf({ cookie: true });
app.set("trust proxy", 1); // trust first proxy
app.use(
  session({
    secret: hash(0, process.env.SECRET),
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
  })
);
app.use(mog("common", { immediate: true }));
app.use(cookieParser());
app.use((req, res, next) => {
  console.log(req.get("User-Agent"));
  if (req.session.views) {
    req.session.views++;
    req.locfess = true;
  } else {
    req.session.views = 1;
    req.locfess = false;
  }
  next();
});
app.use(express.static("public"));
app.set("view engine", "pug");
app.get("/", csrfProtection, (req, res) => {
  res.cookie("XSRF-TOKEN", req.csrfToken());
  if (!req.locfess) {
    res.render(__dirname + "/view/index.pug", {
      hash: false,
      mess: "Look at our Blog",
      csrfToken: req.csrfToken()
    });
  } else {
    res.render(__dirname + "/view/index.pug", {
      hash: false,
      mess: "Welcome back!",
      visits: req.session.views,
      csrfToken: req.csrfToken()
    });
  }
});
app.post(
  "/",
  csrfProtection,
  (err, req, res, next) => {
    if (err.code !== "EBADCSRFTOKEN") {
      next();
    } else {
      res.status(403);
      res.redirect("/#invalid-csurf");
    }
  },
  (req, res) => {
    res.cookie("XSRF-TOKEN", req.csrfToken());
    var observer = new Observable(subscriber => {
      if (req.body.hash) {
        if (req.body.ht) {
          if (req.body.ht == "sha256") {
            subscriber.next({
              hash: true,
              hashd: "SHA256",
              element: hash(0, req.body.hash),
              lasten: req.body.hash,
              csrfToken: req.csrfToken()
            });
          } else if (req.body.ht == "sha1") {
            subscriber.next({
              hash: true,
              hashd: "SHA1",
              element: hash(1, req.body.hash),
              lasten: req.body.hash,
              csrfToken: req.csrfToken()
            });
          } else if (req.body.ht == "md5") {
            subscriber.next({
              hash: true,
              hashd: "MD5",
              element: hash(2, req.body.hash),
              lasten: req.body.hash,
              csrfToken: req.csrfToken()
            });
          } else {
            res.status(400);
            subscriber.next({ hash: false, csrfToken: req.csrfToken() });
          }
        }
      } else {
        res.status(400);
        subscriber.next({ hash: false, csrfToken: req.csrfToken() });
      }
    });
    observer.subscribe(x => {
      res.render(__dirname + "/view/index.pug", x);
    });
  }
);
app.post("/api", (req, res) => {
  var observert = new Observable(subscriber => {
    if (req.body.txt) {
      if (req.body.hash) {
        if (req.body.hash == "sha256") {
          subscriber.next(hash(0, req.body.txt));
        } else if (req.body.hash == "sha1") {
          subscriber.next(hash(1, req.body.txt));
        } else if (req.body.hash == "md5") {
          subscriber.next(hash(2, req.body.txt));
        } else {
          res.status(400);
          subscriber.next("400 - Error");
        }
      }
    } else {
      res.status(400);
      subscriber.next("400 - Error");
    }
  });
  observert.subscribe(x => {
    res.end(x);
  });
});
app.get("/api", (req, res) => {
  var observers = new Observable(subscriber => {
    if (req.query.txt) {
      if (req.query.hash) {
        if (req.query.hash == "sha256") {
          subscriber.next(hash(0, req.query.txt));
        } else if (req.query.hash == "sha1") {
          subscriber.next(hash(1, req.query.txt));
        } else if (req.query.hash == "md5") {
          subscriber.next(hash(2, req.query.txt));
        } else {
          res.status(400);
          subscriber.next("400 - Error");
        }
      }
    } else {
      res.status(400);
      subscriber.next("400 - Error");
    }
  });
  observers.subscribe(x => {
    res.end(x);
  });
});
app.get("/api/help", (req, res) => {
  res.render(__dirname + "/view/help.pug");
});
app.get("/cookie/remove", (req, res) => {
  req.session.destroy(function(err) {
    console.log("User removed Session Cookie");
  });
});
app.get("/*", (req, res) => {
  res.redirect("/");
});
app.use((req, res, next) => {
  //404
  res.status(405);
  res.send("405 - This Method is not allowed");
});
// listen for requests :)
const listener = rel(app,[__dirname+"/view",__dirname+"/public"]).listen(process.env.PORT, function() {
  console.log("Your app is listening on port " + listener.address().port);
});
