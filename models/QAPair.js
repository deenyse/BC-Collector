const mongoose = require('mongoose');

const QAPairSchema = new mongoose.Schema({
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
    textPiece: { type: String, required: true },
    question: { type: String, required: true },
    answer: { type: String, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('QAPair', QAPairSchema);


