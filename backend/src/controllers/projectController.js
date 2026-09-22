const crypto = require('crypto');
const bcrypt = require('bcrypt');
const Project = require('../models/Project');

async function createProject(req, res) {
  try {
    const { name } = req.body;
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ error: 'Project name is required' });
    }

    const rawSecret = crypto.randomBytes(32).toString('hex');
    const tokenHash = await bcrypt.hash(rawSecret, 10);

    const project = new Project({
      name: name.trim(),
      tokenHash
    });

    await project.save();

    const token = `ecdat_${project._id}.${rawSecret}`;
    
    return res.status(201).json({
      projectId: project._id,
      token
    });
  } catch (err) {
    console.error('[projectController] Error creating project:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = { createProject };
