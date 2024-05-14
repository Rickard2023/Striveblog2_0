import GoogleStrategy from "passport-google-oauth20";
import "dotenv/config";
import User from "../models/user.model.js";
import { generateJWT } from "./authenticate.js";

// Opzioni per configurare il servizio OAuth di Google
const options = {
  // Client ID perso dalla console di Google alla registrazione dell'applicazione
  clientID: process.env.G_CLIENT_ID,
  // Client Secret preso dalla console di Google alla registrazione dell'applicazione
  clientSecret: process.env.G_CLIENT_SECRET,
  // Callback da eseguire quando un'utente effettua l'autenticazione all'endpoint
  callbackURL: process.env.G_CB,
};

// Crea un'istanza di Google Strategy
const googleStrategy = new GoogleStrategy(
  options,
  async (_accessToken, _refreshToken, profile, passportNext) => {
    try {
      // Destrutturiamo l'oggetto profile e prendiamo i dati che ci servono
      const { email, given_name, family_name, sub, picture } = profile._json;

      // Verifica se l'utente esiste già nelò database
      const user = await User.findOne({ email });

      // L'utente esiste già nel DB?
      if (user) {
        // L'utente esiste già nel DB

        // Creiamo il token di accesso, utilizzando il servizio di GoogleStrategy
        const accToken = await createAccessToken({
          _id: user._id,
        });

        // Chiamiamo la callback, passando null come errore e accToken come secondo parametro
        passportNext(null, { accToken });
      } else {
        // L'utente non esiste nel DB

        // Crea un nuovo utente
        const newUser = new User({
          username: email,
          googleId: sub,
        });

        // Salva l'utente nel database
        await newUser.save();

        // Genera token
        const accToken = await generateJWT({
          username: newUser.username,
        });

        // Chiamiamo la callback, passando null come errore e accToken come secondo parametro
        passportNext(null, { accToken });
      }
    } catch (error) {
      passportNext(error);
    }
  }
);

export default googleStrategy;