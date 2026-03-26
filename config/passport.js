const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../models/User");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.toLowerCase();
        let user = await User.findOne({ googleId: profile.id });

        if (!user && email) {
          user = await User.findOne({ email });
        }

        if (!user) {
          user = await User.create({
            googleId: profile.id,
            fullName: profile.displayName || "",
            name: profile.displayName || "",
            email,
            role: email === "platonrenaaron@gmail.com" ? "admin" : "user"
          });
        } else if (!user.googleId) {
          user.googleId = profile.id;
          await user.save();
        }

        done(null, user);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});
