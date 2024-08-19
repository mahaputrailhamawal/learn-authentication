import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import { User } from "./models/user.schema";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { Auth } from "./models/auth.schema";

dotenv.config();

mongoose
    .connect(process.env.MONGO_URI as string)
    .then(() => console.log("Mongodb connection success"))
    .catch((error)=> {
        console.log("Mongodb connection failed")
        console.log(error);
    });

const app = express();
app.use(express.json());
app.use(cookieParser());

// REGISTER USER
app.post("/register", async (req, res) => {
    // dekonstruktor data
    const { name, email, password } = req.body;

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // mock data yang akan dimasukkan ke DB
    const newUser = {
        name,
        email,
        password : hashedPassword,
    };

    // insert to db
    const createUser = new User(newUser);
    const data = await createUser.save();

    return res.status(201).json({message: "User register success", data})
});

// LOGIN USER
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // input validation
    if (!email || password.length < 8 ) {
        return res.json({ message: "email should be valid and password should have minimum 8 characters"});
    }

    // find user
    const user = await User.findOne({
        email,
    });

    // check user
    if (!user) {
        return res.status(404).json({ message: "User not found"});
    }

    // check input password
    if (!user.password) {
        return res.status(400).json({ message: "Password not set"});
    }
    // password validation
    const isPassMatch = await bcrypt.compare(password, user.password);

    if (!isPassMatch) {
        return res.status(400).json({ message: "Invalid password"});
    }

    // authorization
    const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
    };

    const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET as string, {
        expiresIn: 300, //5 menit
    });

    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET as string, {
        expiresIn: "7d", //1 minggu
    });

    // save refresh token to DB
    const newRefreshToken = new Auth({
        userId: user.id,
        refreshToken: refreshToken,
    });
    await newRefreshToken.save();

    return res
        .cookie("accessToken", accessToken, { httpOnly: true })
        .cookie("refreshToken", refreshToken, { httpOnly: true })
        .status(200)
        .json({ message: "Login success!"});
});

// Logout user
app.post("/logout", async (req, res) => {
    const { refreshToken } = req.cookies;

    //delete token in DB
    await Auth.findOneAndDelete ({
        refreshToken,
    });

    return res.json({ message: "Logout berhasil..." });
});

// RESOURCES ENDPOINT
app.get("/resources", async(req, res) => {
    const { accessToken, refreshToken } = req.cookies;

    if (accessToken) {
        try {
            jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET as string);
            console.log("Access token masih valid");
            return res.json({ data: "Ini datanya ...." });    
        } catch (error) {
            if (!refreshToken) {
                // if falsem regenerate new access token from refreshToken
                console.log("Refresh token tidak ada");
                return res.status(401).json({ message: "Please re-login...."});
            }
            try {
                // check if refresh token valid
                console.log("Verifikasi refresh token");
                jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET as string);

                // if valid, verify if its exist in database
                console.log("Cek refresh token ke database");
                const activateRefreshToken = await Auth.findOne({
                    refreshToken,
                });

                // if not valid
                if (!activateRefreshToken) {
                    console.log("Refresh token tidak ada di database");
                    return res.status(401).json({ message: "Please re-login...."});
                }

                const payload = jwt.decode(refreshToken) as {id: string, name: string, email: string };
                
                console.log("Buat accessToken baru");
                const newAccessToken = jwt.sign(
                    {
                        id: payload.id,
                        name: payload.name,
                        email: payload.email,
                    }, process.env.JWT_ACCESS_SECRET as string,
                    { expiresIn : 300 }
                )

                return res.cookie("accessToken", newAccessToken, { httpOnly: true }).json({ data: "Ini datanya...." });
            } catch (error) {
                // if invalid, user need to re-login
                return res.status(401).json({ message: "Please re-login...."});
            }
        }
    }
});

app.listen(process.env.PORT, () => {
    console.log(`Server running at port: ${process.env.PORT}`);
});