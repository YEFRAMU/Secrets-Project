import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import GoogleStrategy from "passport-google-oauth2";
import sgMail from "@sendgrid/mail";
import crypto from "crypto"; // NEW - to generate secure random tokens
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day cookie expiry
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Render & Supabase
  },
});

db.connect()
  .then(() => console.log("Connected to DB"))
  .catch((err) => console.error("DB connection error", err));

// Items will be fetched from the database, not hardcoded.

//SMTP setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
// const msg = {
//   to: ["vinceumali81@gmail.com", "noreply.secretapp@gmail.com"],
//   from: {
//     name: "Secret App",
//     email: "noreply.secretapp@gmail.com",
//   },
//   subject: "Welcome to Our Secret App!",
//   text: "Thank you for registering!",
//   html: "<h1>Thank you for registering!</h1>",
// };

// sgMail
//   .send(msg)
//   .then((response) => console.log("Email sent"))
//   .catch((error) => console.error("Error sending email:", error));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const email = req.user.email; // works for both local and Google
      const result = await db.query(
        "SELECT secret FROM auth WHERE email = $1",
        [email]
      );
      const secret =
        result.rows.length === 0 || !result.rows[0].secret
          ? "Submit your secret"
          : result.rows[0].secret;
      res.render("secrets.ejs", { secret });
    } catch (err) {
      console.error("Error fetching secrets:", err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    //req.isAuthenticated() to check if user has already loged in preventing unauthorized access
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM auth WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          // NEW: Generate a unique verification token
          const verificationToken = crypto.randomBytes(32).toString("hex");

          const result = await db.query(
            "INSERT INTO auth (email, password, verified, verification_token) VALUES ($1, $2, $3, $4) RETURNING *",
            [email, hash, false, verificationToken]
          );
          const user = result.rows[0];

          // NEW: Send verification email via SendGrid
          const verificationLink = `${process.env.APP_URL}/verify-email?token=${verificationToken}`;
          const msg = {
            to: email,
            from: {
              name: "Secret App",
              email: "noreply.secretapp@gmail.com",
            },
            subject: "Verify your email",
            html: `
              <h1>Email Verification</h1>
              <p>Thanks for registering! Please verify your email by clicking the link below:</p>
              <a href="${verificationLink}">${verificationLink}</a>
              <p>This link will expire in 24 hours.</p>
            `,
          };
          try {
            await sgMail.send(msg);
            console.log("Verification email sent");
          } catch (error) {
            console.error("Error sending verification email:", error);
          }

          // NEW: Instead of logging in immediately, tell them to check email
          res.send(
            "Registration successful! Please check your email to verify your account."
          );
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// --- NEW ROUTE: EMAIL VERIFICATION ---
app.get("/verify-email", async (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(400).send("Invalid or missing token");
  }

  try {
    // Find user with matching token
    const result = await db.query(
      "SELECT * FROM auth WHERE verification_token = $1",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send("Invalid token or already verified");
    }

    // Update user to set verified = true and clear the token
    await db.query(
      "UPDATE auth SET verified = true, verification_token = NULL WHERE verification_token = $1",
      [token]
    );

    res.send("Email successfully verified! You can now log in.");
  } catch (err) {
    console.error("Error verifying email:", err);
    res.status(500).send("Internal Server Error");
  }
});

//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit", async (req, res) => {
  try {
    const secret = req.body.secret;
    const email = req.user.email;
    await db.query("UPDATE auth SET secret = $1 WHERE email = $2", [
      secret,
      email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.error("Error fetching secrets:", err);
    res.status(500).send("Internal Server Error");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM auth WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        if (!user.verified) {
          // User exists but not verified
          console.log("User not verified");
          return cb(null, false, {
            message: "User not verified. Please check your email.",
          });
        }
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM auth WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO auth (email, password) VALUES ($1, $2)",
            [profile.email, profile.id]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
