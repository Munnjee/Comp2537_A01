require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

//Expires after 1 hour (hour * minutes * seconds * milliseconds)
const expireTime = 1 * 60 * 60 * 1000;

//Users and Passwords (in memory 'database')
var users = [];

/* Secret Information Section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, // Default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

//Home page that checks for authentication status and offers login or sign-up
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    const buttons = `
        <button onclick="window.location.href='/signup'">Sign up</button>
        <br><br>
        <button onclick="window.location.href='/login'">Log in</button>
      `;
    res.send(`<h1>Welcome to Munjee's World</h1>${buttons}`);
  } else {
    const buttons = `
        <button onclick="window.location.href='/members'">Go to Members Area</button>
        <button onclick="window.location.href='/logout'">Log out</button>
      `;
    res.send(`<h1>Hello, ${req.session.name}!</h1>${buttons}`);
  }
});

app.get("/nosql-injection", async (req, res) => {
  var name = req.query.user;

  if (!name) {
    res.send(
      `<h3>No user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + name);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(name);

  // If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello, ${name}!</h1>`);
});

//Sign up function
app.get("/signup", (req, res) => {
  var html = `
      <h1>Create User</h1>
      <form action='/submitUser' method='post'>
      <input name='email' type='email' placeholder='Email'>
      <br><br>
      <input name='name' type='text' placeholder='Name'>
      <br><br>
      <input name='password' type='password' placeholder='Password'>
      <br><br>
      <button>Submit</button>
      </form>
      `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var email = req.body.email;
  var name = req.body.name;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    name: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, name, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var errorMessage = validationResult.error.details[0].message;
    res.send(
      `Huston, we have a problem: ${errorMessage}. Please <a href="/signup">try again!</a>.`
    );
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    password: hashedPassword,
    email: email,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;

  res.redirect("/");
});

app.get("/login", (req, res) => {
  var html = `
      <h1>Log in</h1>
      <form action='/loggingin' method='post'>
      <input name='email' type='text' placeholder='Email'>
      <br><br>
      <input name='password' type='password' placeholder='Password'>
      <br><br>
      <button>Submit</button>
      </form>
      `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("User not found");
    res.send(`User not found. Please <a href="/login">try again</a>.`);
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("Correct Password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
    return;
  } 
  else {
    console.log("Incorrect Password");
    res.send(`Incorrect password. Please <a href="/login">try again</a>.`);
    return;
  }
});

app.get("/loggedin", (req, res) => {
    if (!req.session.authenticated) {
      res.redirect("/login");
    } else {
      res.redirect("/");
    }
  });
  
  app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.log(err);
      } else {
        res.redirect("/");
      }
    });
  });

    const imageURL = [
    "cat.gif",
    "cat2.gif",
    "doge.gif",
    "doge2.gif"
  ];

  app.get("/image/:id", (req, res) => {
  var meme = req.params.id;

  if (meme == 1) {
    res.send(`<img src='/${imageURL[0]}'>`);
  } else if (meme == 2) {
    res.send(`<img src='/${imageURL[1]}'>`);
  } else if (meme == 3) {
    res.send(`<img src='/${imageURL[2]}'>`);
  } else {
    res.send(`<img src='/${imageURL[3]}'>`);
  }
});


  app.get("/members", (req, res) => {
    if (!req.session.name) {
      res.redirect("/");
      return;
    }
  
    const name = req.session.name;
    const image = imageURL[Math.floor(Math.random() * imageURL.length)];
  
    const html = `
      <h1>Hello, ${name}!</h1>
      <img src="/${image}" alt="Random image">
      <br><br>
      <button onclick="window.location.href='/logout'">Log out</button>
    `;
    res.send(html);
  });



app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  const img = `<img src="/404.gif" alt="404"><br>`;
  res.send(img + "<h1>Page not found - 404<h1>");
});

app.listen(port, () => {
  console.log("Assignment 1 listening on port " + port);
});
