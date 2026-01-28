import {PrismaClient, User} from "@prisma/client";
import {Request, Response} from "express"
import bcrypt, {compare} from "bcryptjs";
import jsonwebtoken from 'jsonwebtoken';
import {createTransport} from "nodemailer";
// node built-in crypto, haven't installed in the dependencies
import {randomBytes} from "crypto";
import {OAuth2Client} from "google-auth-library";

export class LoginController {
  constructor(public prisma: PrismaClient) {}

  login = async (req: Request, res: Response) => {
    try {
      const {email, password} = req.body
      if (!email || !password) {
        res.status(400).json({error: "email or password is missing"})
        return
      }

      const user = await this.prisma.user.findUnique({
        where: { email }
      })
      if (!user) {
        res.status(401).json({error: "There is no this user"})
        return
      }
      if (!user.password) {
        res.status(400).json({ 
          error: "This account is registered via Google login. Please login with Google." 
        });
        return;
      }
      if (user.isDeleted) {
        res.json({message: "This user is deactivated"})
        return
      }

      const match = await compare(password, user.password)
      
      if (!match) {
        res.status(400).json({error: "Invalid credentials"})
        return
      }

      const {password: userPassword, ...userPayload} = user
      const token = jsonwebtoken.sign(userPayload, process.env.JWT_SECRET, 
        // { expiresIn: "48h" }
      )

      // not use cookies, use expo-secure-store in the client side
      // res.cookie("accessToken", token, {
      //   httpOnly: true,
      //   // secure: true, // Only over HTTPS
      //   sameSite: "strict", // Protect against CSRF
      //   // maxAge: 48 * 60 * 60 * 1000 // 48 hour
      // })

      res.json({user: userPayload, token})
    } catch (e) {
      console.error(e);
      // 500: Internal server error
      res.status(500).json({ error: "Internal server error" });
    }
  }

  currentUser = async (req: Request & {user: Omit<User, "password">}, res: Response) => {
    res.json(req.user)
  }

  // NOTE: logout now can delete token in the expo-secure-store by deleteItemAsync in client, not call the logout api
  //
  // logout = async (req: Request, res: Response) => {
  //   // not use cookies, use expo-secure-store in the client side
  //   // res.clearCookie("accessToken", {
  //   //   httpOnly: true,
  //   //   // secure: true,
  //   //   sameSite: "strict",
  //   // })

  //   return res.json({ message: "logout success" })
  // }

  register = async (req: Request, res: Response) => {
    const {email, password} = req.body

    if (!email || !password) {
      res.status(400).json({error: "email or password is missing"})
      return
    }

    const user = await this.prisma.user.findUnique({
      where: { email }
    })

    if (user) {
      // NOTE: 409: Conflict
      res.status(409).json({error: "The email is used"})
      return
    }

    const hashPassword = await bcrypt.hash(password, 10)
    const newUser = await this.prisma.user.create(
      {
        data: {
          email,
          password: hashPassword
        }
      }
    )

    res.json({user: newUser.id})
  }

  forgetPassword = async (req: Request, res: Response) => {
    const {email} = req.body
    
    if (!email) {
      res.status(400).json({error: "email is missing"})
      return
    }

    const user = await this.prisma.user.findUnique({
      where: {
        email,
        isDeleted: false
      }
    })

    if (!user) {
      // 404: Not found, resources don't exist
      res.status(404).json({error: "this email hasn't been registered"})
      return
    }

    const token = randomBytes(32).toString("hex")
    await this.prisma.passwordResetToken.create(
      {
        data: {
          email,
          token,
          expiresAt: new Date(Date.now() + 30 * 60 * 1000) // expires after 30 min, Date.now() returns milliseconds
        }
      }
    )

    const resetLink = `wormsorburns://reset/password$token=${token}`

    const transporter = createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_APP_USER_EMAIL,
        pass: process.env.EMAIL_APP_PASSWORD
      }
    })

    await transporter.sendMail({
      from: process.env.EMAIL_APP_USER_EMAIL,
      to: email,
      subject: "Password Reset for app \"Worms or burns\"",
      text: `Hi ${user.displayName ? user.displayName : email},\nTap this link to reset password: ${resetLink}\nThe link will expire after 30 minutes\nThanks`,
       html: `<div>Hi ${user.displayName ? user.displayName : email},</div><p>Tap this link to reset your password:</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <div>The link will expire after 30 minutes</div>
        <div>Thanks</div>`,
    })

    res.json({
      message: "email will be sent if an account exists for this email",
      token
    })
  }

  resetPassword = async (req: Request, res: Response) => {
    const {token, newPassword} = req.body

    if (!token) {
      res.status(401).json({error: "Unauthorized"})
      return
    }

    if (!newPassword) {
      res.status(400).json({error: "There is no new password to reset"})
      return
    }

    const tokenRecord = await this.prisma.passwordResetToken.findUnique({
      where: {
        token
      }
    })

    if (!tokenRecord || !tokenRecord.token) {
      // NOTE: 401: Unauthorized
      res.status(401).json({ error: "Invalid or expired token" });
      return
    }

    await this.prisma.user.update({
      where: {
        email: tokenRecord.email
      },
      data: {
        password: await bcrypt.hash(newPassword, 10)
      }
    })

    res.json({message: "Password reset successful"})
  }

  googleClient = new OAuth2Client(process.env.GOOGLE_WEB_CLIENT_ID)

  googleLogin = async (req: Request, res: Response) => {
    const {token} = req.body

    if (!token) {
      // 400: Bad request
      res.status(400).json({error: "id token is missing"})
      return
    }

    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken: token,
        // audience: process.env.GOOGLE_WEB_CLIENT_ID
        audience: [
          process.env.GOOGLE_IOS_CLIENT_ID,
          process.env.GOOGLE_ANDROID_CLIENT_ID
        ], // accept both platforms
      })

      const payload = ticket.getPayload()

      if (!payload) {
        // 401: Unauthorized
        res.status(401).json({error: "Can't google login"})
        return
      }

      const checkGoogleUserExist = await this.prisma.user.findUnique({
        where: {
          googleSub: payload.sub
        }
      })

      if (checkGoogleUserExist) {
        if (checkGoogleUserExist.isDeleted) {
          res.json({message: "This google account has been deactivated for this app. Please try again later"})
          return
        }

        // NOTE: check password, if password is undefined, it can't be extract from the object
        if (checkGoogleUserExist.password) {
          const {password, ...userPayload} = checkGoogleUserExist
          const jwt = jsonwebtoken.sign(userPayload, process.env.JWT_SECRET)
          
          res.json({user: userPayload, token: jwt})
        } else {
          const jwt = jsonwebtoken.sign(checkGoogleUserExist, process.env.JWT_SECRET)
          res.json({user: checkGoogleUserExist, token: jwt})
        }
        return
      }

      const checkUserExist = await this.prisma.user.findUnique({
        where: {
          email: payload.email
        }
      })

      if (!checkUserExist) {
        const newUser = await this.prisma.user.create({
          data: {
            email: payload.email,
            displayName: payload.name,
            photoURL: payload.picture,
            bio: payload.profile,
            googleSub: payload.sub // sub = subject
          }
        })

        const jwtForNewUser = jsonwebtoken.sign(newUser, process.env.JWT_SECRET)

        res.json({user: newUser, token: jwtForNewUser})
        return
      }

      const {id, displayName, photoURL, bio} = checkUserExist

      const user = await this.prisma.user.update({
        where: { id },
        data: {
          // payload is from Google login ticket
          displayName: displayName ? displayName : payload.name,
          photoURL: photoURL ? photoURL : payload.picture,
          bio: bio ? bio : payload.profile,
          googleSub: payload.sub
        }
      })

      if (user.isDeleted) {
        res.status(400).json({error: "This user is deactivated"})
        return
      }

      // NOTE: user must have password because this user is registered by classic method, and not login by google before
      // don't need to check user.pasword exist
      // if (user.password) {
      //   const {password, ...userPayload} = checkGoogleUserExist
      //   const jwt = jsonwebtoken.sign(userPayload, process.env.JWT_SECRET)
      //   res.json({user: userPayload, token: jwt})
      // } else {
      //   const jwt = jsonwebtoken.sign(user, process.env.JWT_SECRET)
      //   res.json({user, token: jwt})
      // }

      // ERROR: Cannot destructure property 'password' of 'checkGoogleUserExist' as it is null.
      // NOTE: checkGoogleUserExist shouldn't be used here
      // const {password, ...userPayload} = checkGoogleUserExist

      const {password, ...userPayload} = user
      const jwt = jsonwebtoken.sign(userPayload, process.env.JWT_SECRET)
      res.json({user: userPayload, token: jwt})
    } catch (e) {
      console.error(e);
      res.status(401).json({ error: "Invalid token" });
    }
  }
}