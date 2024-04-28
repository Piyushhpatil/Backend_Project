import connectDB from './db/index.js'
import dotenv from "dotenv"

dotenv.config({
    path: './env'
})


connectDB()
.then(() => {
    app.on("error", (error) => {
        console.log("Err:", error);
        throw error
    })
    app.listen(process.env.PORT || 8000, ()=> {
        console.log(`Server is running at port: ${process.env.PORT}`);
    })
})
.catch((err) => {
    console.log("MongoDB connection failed !!! ", err);
})
