import { asyncHandler } from '../utils/asyncHandler.js'
import {ApiError} from '../utils/ApiError.js'
import { User } from '../models/user.model.js'
import { uploadCloudinary } from '../utils/cloudinary.js'
import { ApiResponse } from '../utils/ApiResponse.js'


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

//First check the email and send to database
//same for password
// 


export { registerUser }