import config from "../config";

export const getBkashIdToken = async () => {
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
            app_secret: config.bkash_app_ssecret,
        })
    })


    const result = await response.json();
    return result;

}
