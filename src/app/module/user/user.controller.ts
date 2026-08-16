import { Request, Response } from "express";
import httpStatus from 'http-status';
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";

const uploadProfileImage = catchAsync(async (req: Request, res: Response) => {

    console.log(req.file);

    if (!req.file) {
        throw new Error("No File Provided.")
    }

    const userId = req.user?.userId

    // const result = await UserServices.uploadProfileImage(req.file?.buffer, userId!)

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: "New tokens generated successfully",
        data: null,
    });
})
export const UserController = {
    uploadProfileImage
}