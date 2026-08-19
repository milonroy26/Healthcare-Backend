import config from "../config";
import { redisClient } from "./redis";

export const getBkashIdToken = async () => {
    try {
        const IdTokenKey = "bkash:idTOken";
        const RefreshTokenKey = "bkash:refreshToken";

        const bkashIdTokenTTL = await redisClient.ttl(IdTokenKey)
        let bkashIdToken = await redisClient.get(IdTokenKey);


        const bkashRefreshToken = await redisClient.get(RefreshTokenKey)
        const bkashRefreshTokenTTL = await redisClient.ttl(RefreshTokenKey)


        if (bkashIdTokenTTL > 600) {
            return bkashIdToken
        }

        const response = await fetch(`${config.bkash_base_url}/tokenized/checkout/token/grant`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
                username: config.bkash_username,
                password: config.bkash_password
            },
            body: JSON.stringify({
                app_key: config.bkash_app_key,
                app_secret: config.bkash_app_secret
            })
        })

        if (!response.ok) {
            throw new Error("Bkash Access Token Grant Failed")
        }

        const result = await response.json();

        //* store id token in redis for 1 hour
        await redisClient.set(IdTokenKey, result.id_token, {
            expiration: {
                type: "EX",
                value: 60 * 60
            }
        })

        //* store refresh token in redis for 28 days
        await redisClient.set(RefreshTokenKey, result.refresh_token, {
            expiration: {
                type: "EX",
                value: 60 * 60 * 24 * 28
            }
        })

        return result.id_token
    } catch (error: any) {
        throw new Error(error.message)
    }
}
