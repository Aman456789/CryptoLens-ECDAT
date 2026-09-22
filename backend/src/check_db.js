const mongoose = require('mongoose');
const Asset = require('./models/Asset');
const Project = require('./models/Project');

async function run() {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://ecdat:supersecret@localhost:27017/ecdat?authSource=admin');
  const projects = await Project.find({});
  console.log('Projects:', projects);
  const assets = await Asset.find({});
  console.log('Assets:', assets);
  process.exit(0);
}

run().catch(console.error);
