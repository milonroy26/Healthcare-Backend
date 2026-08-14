import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { TokenPayload } from 'google-auth-library'
import { JwtPayload, SignOptions } from 'jsonwebtoken'
import { AuthProvider, Role, UserStatus } from '../../../generated/prisma/enums'
import config from '../../config'
import { googleClient } from '../../lib/googleAuth'
import { prisma } from '../../lib/prisma'
import { jwtUtils } from '../../utils/jwt'

import ejs from "ejs"
import path from "path"
import { transporter } from '../../lib/nodemailer'
import { redisClient } from '../../lib/redis'
import {
    IForgotPasswordPayload,
    IGoogleLoginPayload,
    ILoginUserPayload,
    IRegisterPatientPayload,
    IRequestUser,
    IResetPasswordPayload
} from './auth.interface'



const registerPatient = async (payload: IRegisterPatientPayload) => {
    const { name, password } = payload
    const email = payload.email.trim().toLowerCase()

    const isUserExists = await prisma.user.findUnique({
        where: { email },
    })

    if (isUserExists) {
        throw new Error('User with this email already exists')
    }

    const hashedPassword = await bcrypt.hash(password, 8)

    const createdUser = await prisma.user.create({
        data: {
            name,
            email,
            password: hashedPassword,
            role: Role.PATIENT,
            status: UserStatus.ACTIVE,
            emailVerified: false,
            patient: {
                create: { name, email },
            },
        },
        omit: { password: true },
        include: { patient: true },
    })

    const { patient, ...user } = createdUser
    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    }

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret,
        config.jwt_access_expires_in as SignOptions
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret,
        config.jwt_refresh_expires_in as SignOptions
    );

    return {
        user,
        patient,
        accessToken,
        refreshToken
    }
}

const loginUser = async (payload: ILoginUserPayload) => {
    // 1. Payload & Email Validation Check
    if (!payload?.email) {
        throw new Error('Email is required');
    }

    if (!payload?.password) {
        throw new Error('Password is required');
    }

    const { password } = payload;
    // 2. Safe trim & toLowerCase with optional chaining
    const email = payload.email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user) {
        throw new Error('User not found');
    }

    if (user.status === UserStatus.BLOCKED) {
        throw new Error('User is blocked');
    }

    if (user.isDeleted || user.status === UserStatus.DELETED) {
        throw new Error('User is deleted');
    }

    if (!user.password) {
        throw new Error('Invalid credentials');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
        throw new Error('Invalid credentials');
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    };

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret,
        config.jwt_access_expires_in as SignOptions
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret,
        config.jwt_refresh_expires_in as SignOptions
    );

    return {
        accessToken,
        refreshToken
    };
};

const getMe = async (user: IRequestUser) => {
    const isUserExists = await prisma.user.findUnique({
        where: {
            id: user.userId,
        },
        include: {
            patient: true,
        },
        omit: {
            password: true,
        },
    })

    if (!isUserExists) {
        throw new Error('User not found')
    }

    return isUserExists
}

const refreshToken = async (token: string) => {
    const verifiedRefreshToken = jwtUtils.verifyToken(token, config.jwt_refresh_secret)

    if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
        throw new Error(config.node_env === 'development' ? verifiedRefreshToken.error : 'Invalid refresh token')
    }

    const data = verifiedRefreshToken.data as JwtPayload

    const user = await prisma.user.findUnique({
        where: { id: data.userId },
    })

    if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
        throw new Error('User is inactive or not found')
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    }

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret,
        config.jwt_access_expires_in as SignOptions
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret,
        config.jwt_refresh_expires_in as SignOptions
    );

    return {
        accessToken,
        refreshToken
    }
}

const googleLogin = async (payload: IGoogleLoginPayload) => {

    let googleIdTokenPayload: TokenPayload | null | undefined = null;

    try {
        //* login ticket
        const ticket = await googleClient.verifyIdToken({
            idToken: payload.idToken,
            audience: config.google_client_id
        })

        googleIdTokenPayload = ticket.getPayload()

    } catch (error) {
        console.log("Google Id Token Verification Error:", error)
        throw new Error('Invalid Or Expired Google Id Token')
    }

    if (!googleIdTokenPayload) {
        throw new Error('Invalid Or Expired Google Id Token')
    }

    if (!googleIdTokenPayload.email) {
        throw new Error('Google Email Not Found')
    }

    if (!googleIdTokenPayload.name) {
        throw new Error('User Name Not Found')
    }

    //* check if user exist
    const ifPatientExistWithGoogleAuth = await prisma.user.findFirst({
        where: {
            email: googleIdTokenPayload.email,
            role: Role.PATIENT,
            googleId: googleIdTokenPayload.sub,
        }
    });

    let user = ifPatientExistWithGoogleAuth

    if (!user) {
        const ifPatientExistWithCredentials = await prisma.user.findUnique({
            where: {
                email: googleIdTokenPayload.email,
                role: Role.PATIENT,
                authProvider: AuthProvider.CREDENTIALS
            }
        });

        if (ifPatientExistWithCredentials) {

            if (!ifPatientExistWithCredentials.emailVerified) {
                throw new Error("Email Not Verified")
            }

            if (ifPatientExistWithCredentials.status === UserStatus.BLOCKED) {
                throw new Error("User is blocked")
            }

            if (ifPatientExistWithCredentials.isDeleted || ifPatientExistWithCredentials.status === UserStatus.DELETED) {
                throw new Error("User is deleted")
            }

            user = await prisma.user.update({
                where: {
                    id: ifPatientExistWithCredentials.id
                },
                data: {
                    googleId: googleIdTokenPayload.sub,
                    emailVerified: true
                }
            })
        }
        else {
            // create new user with google auth
            user = await prisma.user.create({
                data: {
                    name: googleIdTokenPayload.name,
                    email: googleIdTokenPayload.email,
                    role: Role.PATIENT,
                    googleId: googleIdTokenPayload.sub,
                    authProvider: AuthProvider.GOOGLE,
                    emailVerified: true,
                    patient: {
                        create: {
                            name: googleIdTokenPayload.name,
                            email: googleIdTokenPayload.email
                        }
                    }
                }
            })
        }
    }

    if (!user) {
        throw new Error('User not found')
    }

    if (user.status === UserStatus.BLOCKED) {
        throw new Error('User is blocked')
    }

    if (user.isDeleted || user.status === UserStatus.DELETED) {
        throw new Error('User is deleted')
    }

    if (user.password === null && user.googleId !== null) {
        throw new Error("User Allready Has Account Registered With Google. Try To Login with Google")
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    }

    const accessToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_access_secret,
        config.jwt_access_expires_in as SignOptions
    );

    const refreshToken = jwtUtils.createToken(
        jwtPayload,
        config.jwt_refresh_secret,
        config.jwt_refresh_expires_in as SignOptions
    );

    return {
        accessToken,
        refreshToken
    }

}

const forgotPassword = async (payload: IForgotPasswordPayload) => {
    const { email } = payload;

    const isUserExist = await prisma.user.findUnique({
        where: { email }
    })

    if (!isUserExist) {
        throw new Error('User Does Not Exist');
    }

    if (isUserExist.status === "BLOCKED") {
        throw new Error('User is blocked');
    }

    if (!isUserExist.emailVerified) {
        throw new Error('Email Not Verified');
    }

    if (isUserExist.isDeleted || isUserExist.status === "DELETED") {
        throw new Error('User is deleted');
    }

    if (isUserExist.googleId && isUserExist.authProvider === "GOOGLE") {
        throw new Error('User Allready Has Account Registered With Google. Try To Login with Google');
    }

    const otp = crypto.randomInt(100000, 1000000).toString();
    const key = `forgot-password-otp:${isUserExist.email}`

    await redisClient.set(key, otp, {
        expiration: {
            type: "EX",
            value: 5 * 60,
        }
    })

    const expirationSeconds = 5 * 60
    const tempatePath = path.join(process.cwd(), "src/app/templates/forgot-password.ejs")
    const templateData = {
        name: isUserExist.name,
        otp,
        expirationMinutes: expirationSeconds / 60
    }
    const html = await ejs.renderFile(tempatePath, templateData)

    await transporter.sendMail({
        from: config.email_sender,
        to: isUserExist.email,
        subject: "Forgot Password OTP",
        html
    })
}

const resetPassword = async (payload: IResetPasswordPayload) => {

    const { email, otp, newPassword } = payload;

    const isUserExist = await prisma.user.findUnique({
        where: {
            email
        }
    });

    if (!isUserExist) {
        throw new Error("User Does Not Exist!")
    };

    if (isUserExist.status === "BLOCKED") {
        throw new Error("User is Blocked")
    }

    if (!isUserExist.emailVerified) {
        throw new Error("User Not Verified")
    }

    if (isUserExist.isDeleted || isUserExist.status === "DELETED") {
        throw new Error("User is Deleted")
    }

    if (isUserExist.googleId && isUserExist.authProvider === "GOOGLE") {
        throw new Error("User Has Account With Google")
    }

    const key = `forgot-password-otp:${isUserExist.email}`

    const redisOtp = await redisClient.get(key)

    if (!redisOtp) {
        throw new Error("Invalid OTP")
    }

    if (redisOtp !== otp) {
        throw new Error("OTP Does Not Match")
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, Number(config.bcrypt_salt_rounds));

    await prisma.user.update({
        where: {
            email: isUserExist.email
        },
        data: {
            password: hashedNewPassword
        }
    });

    await redisClient.del([key]);

    const tempatePath = path.join(process.cwd(), "src/app/templates/reset-password-success.ejs")
    const templateData = {
        name: isUserExist.name
    }
    const html = await ejs.renderFile(tempatePath, templateData)

    await transporter.sendMail({
        from: config.email_sender,
        to: isUserExist.email,
        subject: "Password Changed",
        html
    })
}

export const AuthService = {
    registerPatient,
    loginUser,
    getMe,
    refreshToken,
    googleLogin,
    forgotPassword,
    resetPassword
}
