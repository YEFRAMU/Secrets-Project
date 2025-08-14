import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import GoogleStrategy from "passport-google-oauth2";
import nodemailer from "nodemailer";
import { google } from "googleapis";
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

// Gmail OAuth2 setup (after dotenv.config())
const gmailOAuth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.GMAIL_REDIRECT_URI
);

async function sendVerificationEmail(to, verificationLink) {
  gmailOAuth2Client.setCredentials({
    refresh_token: process.env.GMAIL_REFRESH_TOKEN,
  });
  const accessTokenObj = await gmailOAuth2Client.getAccessToken();
  const accessToken = accessTokenObj.token || accessTokenObj;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.GMAIL_SENDER_EMAIL,
      clientId: process.env.GMAIL_CLIENT_ID,
      clientSecret: process.env.GMAIL_CLIENT_SECRET,
      refreshToken: process.env.GMAIL_REFRESH_TOKEN,
      accessToken,
    },
  });

  await transporter.sendMail({
    from: `"Secret App" <${process.env.GMAIL_SENDER_EMAIL}>`,
    to,
    subject: "Verify your email",
    html: `
      <h1>Email Verification</h1>
      <p>Thanks for registering! Please verify your email by clicking the link below:</p>
      <a href="${verificationLink}">${verificationLink}</a>
      <p>This link will expire in 24 hours.</p>
    `,
  });
}

// (Optional) route to inspect OAuth callback if you ever add that redirect locally
app.get("/oauth2callback", async (req, res) => {
  res.send("OAuth playground used for tokens; no handler needed here.");
});

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
      const email = req.user.email;
      const result = await db.query(
        "SELECT secret FROM google_auth WHERE email = $1",
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
    const checkResult = await db.query(
      "SELECT * FROM google_auth WHERE email = $1",
      [email]
    );

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const verificationToken = crypto.randomBytes(32).toString("hex");

          await db.query(
            "INSERT INTO google_auth (email, password, verified, verification_token) VALUES ($1, $2, $3, $4) RETURNING *",
            [email, hash, false, verificationToken]
          );

          const verificationLink = `${process.env.APP_URL}/verify-email?token=${verificationToken}`;
          try {
            await sendVerificationEmail(email, verificationLink);
            console.log("Verification email sent (Gmail)");
          } catch (error) {
            console.error("Error sending verification email:", error);
          }

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

// --- EMAIL VERIFICATION ---
app.get("/verify-email", async (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(400).send("Invalid or missing token");
  }

  try {
    const result = await db.query(
      "SELECT * FROM google_auth WHERE verification_token = $1",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send("Invalid token or already verified");
    }

    await db.query(
      "UPDATE google_auth SET verified = true, verification_token = NULL WHERE verification_token = $1",
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
    await db.query("UPDATE google_auth SET secret = $1 WHERE email = $2", [
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
      const result = await db.query(
        "SELECT * FROM google_auth WHERE email = $1 ",
        [username]
      );
      if (result.rows.length > 0) {
        const user = result.rows[0];
        if (!user.verified) {
          console.log("User not verified");
          return cb(null, false, {
            message: "User not verified. Please check your email.",
          });
        }
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
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
        const result = await db.query(
          "SELECT * FROM google_auth WHERE email = $1",
          [profile.email]
        );
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO google_auth (email, verified) VALUES ($1, $2) RETURNING *",
            [profile.email, true]
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
