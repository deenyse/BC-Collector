const mongoose = require('mongoose');

const FileSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    fileLink: { type: String, required: false }, // Optional link to file
    uploadedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('File', FileSchema);


