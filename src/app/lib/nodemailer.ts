import nodemailer from "nodemailer"
import config from "../config"

export const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: config.smpt_user,
        pass: config.smpt_password
    }
})
