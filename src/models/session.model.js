import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: true
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    userAgent: {
        type: String,
        required: [true, "User agent is require"]
    },
    ipAddress: {
        type: String,
        required: [true, "IP address is required"]
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: "7d" // Automatically delete sessions after 7 days
    },
    revoked: {
        type: Boolean,
        default: false

    }
}, {
    timestamps: true

}
);

const sessionModel = mongoose.model("sessions", sessionSchema);
export default sessionModel;
