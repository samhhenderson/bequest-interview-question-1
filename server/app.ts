import express from "express";
import cors from "cors"; 
import crypto from "crypto";

const PORT = 8080;
const app = express();

// Database is modified to include a hash and timestamp, so we can retrieve data
// at last verified change. Database would be immutable and backed up.
const database = [{ 
  data: "Hello World!", 
  hash: "091ba07212a35a347c5983c0b4a628ddb59cfd540a0a770560b5d5f6d307675e", 
  timestamp: 0
},
{ 
  data: "This is bad data!", 
  hash: "091ba07212a35a347c5983c0b4a628ddb59cfd540a0a770560b5d5f6d307675e", 
  timestamp: 1
}];

// Our super secret key to hash data with
const SUPER_SECRET_KEY = 'supersecretkey';

app.use(cors());
app.use(express.json());

// Controllers

type VerifyController = {
  hash: express.RequestHandler;
  validate: express.RequestHandler;
}

const verify: VerifyController = {

  // We're goign to use a HMAC to hash the data with a key so bad actors
  // can't just send us a sha256 hash of the bad data they want to store
  hash: (req, res, next) => {
    req.body.hash = crypto.createHmac("sha256", SUPER_SECRET_KEY)
      .update(req.body.data)
      .digest("hex");
    next();
  },

  // When we verify data we'll check the hash against the data
  validate: (req, res, next) => {
    let error = false;

    database.sort((a, b) => b.timestamp - a.timestamp);

    for (let i = 0; i < database.length; i++) {
      const hash = crypto.createHmac("sha256", SUPER_SECRET_KEY)
        .update(database[i].data)
        .digest("hex");
      
      // We could also search through all data every verification and return 
      // the most recent verified data, but this could take a while; We'll asssume
      // data is verified often enough that we don't need to do this.
      if (hash === database[i].hash) {
        error ?
          res.locals.message = 'Corrupt data detected! Last verified data shown.'
          : res.locals.message = 'Data verified!';
        res.locals.data = database[i].data;
        break;
      } else error = true;

    };
    if (error === true && res.locals.data === undefined) {
      res.locals.message = 'Corrupt data detected! No verified data found.';
      res.locals.data = null;
    }

    next();
  }
};

// Routes

app.get("/", (req, res) => {
  database.sort((a, b) => b.timestamp - a.timestamp);
  res.json(database[0]);
});

app.post("/", verify.hash, (req, res) => {
  database.push({ data: req.body.data, hash: req.body.hash, timestamp: Date.now() });
  console.log(database)
  res.sendStatus(200);
});

// New Route to verify data
app.get("/verify", verify.validate, (req, res) => {
  res.status(200).json({message: res.locals.message, data: res.locals.data})
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
