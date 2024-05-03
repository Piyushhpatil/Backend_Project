import { asyncHandler } from '../utils/asyncHandler.js'
import {ApiError} from '../utils/ApiError.js'
import { User } from '../models/user.model.js'
import { uploadCloudinary } from '../utils/cloudinary.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import jwt from 'jsonwebtoken'


const generateAccessTokenAndRefreshToken = async(userID) => {
    try {
        const user = await User.findById(userID)
        const accessToken = user.generateAccessToken
        const refreshToken = user.refreshAccessToken
        user.refreshToken = refreshToken
        user.save({validateBeforeSave: false})

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access tokens" )
    }

    return { accessToken, refreshToken}
}


const registerUser = asyncHandler( async (req, res) => {
    const {fullName, email, username, password } = req.body
    console.log("email: ", email);

    // if (fullName === ""){
    //     throw new ApiError(400, "full name is required")
    // }
    if (
        [fullName, email, username, password].some((field) => field?.trim() ==="")
    ) {
        throw new ApiError(400, "All field are required")
    } 

    const existedUser = await User.findOne({
        $or: [{username} ,{email} ]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path
    let coverImageLocalPath ;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path      
    }


    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required")
    }

    const avatar = await uploadCloudinary(avatarLocalPath)
    const coverImage = await uploadCloudinary(coverImageLocalPath)

    if (!avatar){
        throw new ApiError(400, "Avatar is required")
    }

    const user = await User.create({
        fullName ,
        email , 
        username: username.toLowerCase , 
        password , 
        avatar : avatar.url, 
        coverImage:coverImage?.url || ""
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser){
        throw new ApiError(500, "Something went wrong while registering User")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "Successfully registered User")
    )
})

const loginUser = asyncHandler(async (req, res) => {
    
    const {email, username , password} = req.body

    if (!email || !username){
        throw new ApiError(400, "Username or email is required")
    }

    const user = await User.findOne({
        $or: [{ username },{ email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid Users credentials")
    }

    const {accessToken, refreshToken} = await generateAccessTokenAndRefreshToken(user._id)


    const loggedInUser = await User.findById(user._id).
    select("-password, -refreshToken")

    const options = {
        httOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(new ApiResponse(200, {
        user: loggedInUser,  accessToken, refreshToken
    }, "Successfully logged in User"))

})

const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out succesfully"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid user token")
        }
    
        if (incomingRefreshToken != user?.refreshToken){
            throw new ApiError(401, "Refresh token is expired or used")
        }
    
        const options = {
            httOnly: true,
            secure: true
        }
    
        const {accessToken, newrefreshToken} =await generateAccessTokenAndRefreshToken(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newrefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newrefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "invalid refresh token")   
    }
})

export { registerUser, loginUser, logoutUser, refreshAccessToken }