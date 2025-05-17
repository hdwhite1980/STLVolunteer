/**
 * STL Tornado Relief - Volunteer Management System
 * 
 * Single-file server implementation for AWS Lambda deployment
 * This file contains all backend code in one place for easy deployment
 * The frontend remains separate and is served as static files
 */

/*****************************************************************************
 * DEPENDENCIES
 *****************************************************************************/
const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');
const path = require('path');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const Handlebars = require('handlebars');

/*****************************************************************************
 * CONFIGURATION
 *****************************************************************************/
// Load environment variables
require('dotenv').config();

// Environment variables with defaults
const ENV = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 3000,
  AWS_REGION: process.env.AWS_REGION || 'us-east-1',
  VOLUNTEERS_TABLE: process.env.DYNAMODB_VOLUNTEERS_TABLE || 'StlReliefVolunteers',
  TASKS_TABLE: process.env.DYNAMODB_TASKS_TABLE || 'StlReliefTasks',
  RESOURCES_TABLE: process.env.DYNAMODB_RESOURCES_TABLE || 'StlReliefResources',
  COGNITO_USER_POOL_ID: process.env.COGNITO_USER_POOL_ID,
  COGNITO_APP_CLIENT_ID: process.env.COGNITO_APP_CLIENT_ID,
  S3_BUCKET: process.env.S3_BUCKET || 'stl-tornado-relief-uploads',
  JWT_SECRET: process.env.JWT_SECRET || 'dev-secret-key-change-in-production',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1d',
  EMAIL_FROM: process.env.EMAIL_FROM || 'noreply@stl-tornado-relief.org'
};

// Configure AWS SDK
AWS.config.update({
  region: ENV.AWS_REGION
});

// AWS Service clients
const dynamoDB = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();
const ses = new AWS.SES();
const sns = new AWS.SNS();
const cognitoISP = new AWS.CognitoIdentityServiceProvider();

/*****************************************************************************
 * ERROR HANDLING UTILITIES
 *****************************************************************************/
// Custom application error
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Async function wrapper to handle errors
const catchAsync = fn => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

// Global error handler middleware
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Development error response (more detailed)
  if (ENV.NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  } 
  // Production error response (less information)
  else {
    // Operational, trusted error: send message to client
    if (err.isOperational) {
      return res.status(err.statusCode).json({
        status: err.status,
        message: err.message
      });
    }
    // Programming or unknown error: don't leak error details
    console.error('ERROR 💥', err);
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
};

/*****************************************************************************
 * DATABASE MODELS
 *****************************************************************************/

/**
 * Volunteer Model
 */
class Volunteer {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.firstName = data.firstName;
    this.lastName = data.lastName;
    this.email = data.email;
    this.phone = data.phone;
    this.skills = data.skills || [];
    this.availability = data.availability || {};
    this.location = data.location;
    this.emergencyContact = data.emergencyContact;
    this.transportation = data.transportation;
    this.equipment = data.equipment || [];
    this.status = data.status || 'active';
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  static async create(data) {
    const volunteer = new Volunteer(data);
    await dynamoDB.put({
      TableName: ENV.VOLUNTEERS_TABLE,
      Item: volunteer
    }).promise();
    return volunteer;
  }

  static async findById(id) {
    const result = await dynamoDB.get({
      TableName: ENV.VOLUNTEERS_TABLE,
      Key: { id }
    }).promise();
    return result.Item ? new Volunteer(result.Item) : null;
  }

  static async findByEmail(email) {
    const result = await dynamoDB.query({
      TableName: ENV.VOLUNTEERS_TABLE,
      IndexName: 'EmailIndex',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: {
        ':email': email
      }
    }).promise();
    return result.Items.length > 0 ? new Volunteer(result.Items[0]) : null;
  }

  static async update(id, data) {
    const volunteer = await this.findById(id);
    if (!volunteer) return null;

    const updatedVolunteer = new Volunteer({
      ...volunteer,
      ...data,
      id,
      updatedAt: new Date().toISOString()
    });

    await dynamoDB.put({
      TableName: ENV.VOLUNTEERS_TABLE,
      Item: updatedVolunteer
    }).promise();

    return updatedVolunteer;
  }

  static async list(filters = {}) {
    let params = {
      TableName: ENV.VOLUNTEERS_TABLE
    };

    // Apply filters if provided
    if (Object.keys(filters).length > 0) {
      let filterExpression = [];
      let expressionAttributeValues = {};
      let expressionAttributeNames = {};

      Object.entries(filters).forEach(([key, value]) => {
        const attributeName = `#${key}`;
        const attributeValue = `:${key}`;
        filterExpression.push(`${attributeName} = ${attributeValue}`);
        expressionAttributeNames[attributeName] = key;
        expressionAttributeValues[attributeValue] = value;
      });

      params.FilterExpression = filterExpression.join(' AND ');
      params.ExpressionAttributeNames = expressionAttributeNames;
      params.ExpressionAttributeValues = expressionAttributeValues;
    }

    const result = await dynamoDB.scan(params).promise();
    return result.Items.map(item => new Volunteer(item));
  }
}

/**
 * Task Model
 */
class Task {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.title = data.title;
    this.description = data.description;
    this.location = data.location;
    this.priority = data.priority || 'medium'; // low, medium, high, urgent
    this.requiredSkills = data.requiredSkills || [];
    this.volunteerCount = data.volunteerCount || 1;
    this.assignedVolunteers = data.assignedVolunteers || [];
    this.status = data.status || 'open'; // open, assigned, in-progress, completed, cancelled
    this.startDate = data.startDate;
    this.endDate = data.endDate;
    this.createdBy = data.createdBy;
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  static async create(data) {
    const task = new Task(data);
    await dynamoDB.put({
      TableName: ENV.TASKS_TABLE,
      Item: task
    }).promise();
    return task;
  }

  static async findById(id) {
    const result = await dynamoDB.get({
      TableName: ENV.TASKS_TABLE,
      Key: { id }
    }).promise();
    return result.Item ? new Task(result.Item) : null;
  }

  static async update(id, data) {
    const task = await this.findById(id);
    if (!task) return null;

    const updatedTask = new Task({
      ...task,
      ...data,
      id,
      updatedAt: new Date().toISOString()
    });

    await dynamoDB.put({
      TableName: ENV.TASKS_TABLE,
      Item: updatedTask
    }).promise();

    return updatedTask;
  }

  static async list(filters = {}) {
    let params = {
      TableName: ENV.TASKS_TABLE
    };

    // If status filter is provided, use the GSI
    if (filters.status) {
      params.IndexName = 'StatusCreatedAtIndex';
      params.KeyConditionExpression = 'status = :status';
      params.ExpressionAttributeValues = {
        ':status': filters.status
      };

      // Add date range if provided
      if (filters.startDate && filters.endDate) {
        params.KeyConditionExpression += ' AND createdAt BETWEEN :startDate AND :endDate';
        params.ExpressionAttributeValues[':startDate'] = filters.startDate;
        params.ExpressionAttributeValues[':endDate'] = filters.endDate;
      }

      delete filters.status;
      delete filters.startDate;
      delete filters.endDate;
    }

    // Apply remaining filters
    if (Object.keys(filters).length > 0) {
      let filterExpression = [];
      let expressionAttributeValues = params.ExpressionAttributeValues || {};
      let expressionAttributeNames = {};

      Object.entries(filters).forEach(([key, value]) => {
        const attributeName = `#${key}`;
        const attributeValue = `:${key}`;
        filterExpression.push(`${attributeName} = ${attributeValue}`);
        expressionAttributeNames[attributeName] = key;
        expressionAttributeValues[attributeValue] = value;
      });

      params.FilterExpression = filterExpression.join(' AND ');
      params.ExpressionAttributeNames = expressionAttributeNames;
      params.ExpressionAttributeValues = expressionAttributeValues;
    }

    // Decide whether to query or scan
    const operation = params.KeyConditionExpression ? 'query' : 'scan';
    const result = await dynamoDB[operation](params).promise();
    return result.Items.map(item => new Task(item));
  }

  static async assignVolunteers(taskId, volunteerIds) {
    const task = await this.findById(taskId);
    if (!task) return null;

    task.assignedVolunteers = volunteerIds;
    task.status = 'assigned';
    return await this.update(taskId, task);
  }
}

/**
 * Resource Model
 */
class Resource {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.name = data.name;
    this.type = data.type; // supply, equipment, donation, facility
    this.description = data.description;
    this.quantity = data.quantity || 1;
    this.location = data.location;
    this.status = data.status || 'available'; // available, reserved, deployed, depleted
    this.tags = data.tags || [];
    this.assignedTo = data.assignedTo;
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  static async create(data) {
    const resource = new Resource(data);
    await dynamoDB.put({
      TableName: ENV.RESOURCES_TABLE,
      Item: resource
    }).promise();
    return resource;
  }

  static async findById(id) {
    const result = await dynamoDB.get({
      TableName: ENV.RESOURCES_TABLE,
      Key: { id }
    }).promise();
    return result.Item ? new Resource(result.Item) : null;
  }

  static async update(id, data) {
    const resource = await this.findById(id);
    if (!resource) return null;

    const updatedResource = new Resource({
      ...resource,
      ...data,
      id,
      updatedAt: new Date().toISOString()
    });

    await dynamoDB.put({
      TableName: ENV.RESOURCES_TABLE,
      Item: updatedResource
    }).promise();

    return updatedResource;
  }

  static async list(filters = {}) {
    let params = {
      TableName: ENV.RESOURCES_TABLE
    };

    // If type filter is provided, use the GSI
    if (filters.type) {
      params.IndexName = 'TypeIndex';
      params.KeyConditionExpression = 'type = :type';
      params.ExpressionAttributeValues = {
        ':type': filters.type
      };
      delete filters.type;
    }

    // Apply remaining filters
    if (Object.keys(filters).length > 0) {
      let filterExpression = [];
      let expressionAttributeValues = params.ExpressionAttributeValues || {};
      let expressionAttributeNames = {};

      Object.entries(filters).forEach(([key, value]) => {
        const attributeName = `#${key}`;
        const attributeValue = `:${key}`;
        filterExpression.push(`${attributeName} = ${attributeValue}`);
        expressionAttributeNames[attributeName] = key;
        expressionAttributeValues[attributeValue] = value;
      });

      params.FilterExpression = filterExpression.join(' AND ');
      params.ExpressionAttributeNames = expressionAttributeNames;
      params.ExpressionAttributeValues = expressionAttributeValues;
    }

    // Decide whether to query or scan
    const operation = params.KeyConditionExpression ? 'query' : 'scan';
    const result = await dynamoDB[operation](params).promise();
    return result.Items.map(item => new Resource(item));
  }

  static async adjustQuantity(id, adjustment) {
    const resource = await this.findById(id);
    if (!resource) return null;

    const newQuantity = resource.quantity + adjustment;
    if (newQuantity < 0) {
      throw new Error('Insufficient quantity');
    }

    resource.quantity = newQuantity;
    if (newQuantity === 0) {
      resource.status = 'depleted';
    }

    return await this.update(id, resource);
  }
}

/**
 * User Model for Authentication
 */
class User {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.email = data.email;
    this.password = data.password;
    this.firstName = data.firstName;
    this.lastName = data.lastName;
    this.role = data.role || 'volunteer'; // volunteer, coordinator, admin
    this.volunteerId = data.volunteerId; // Link to volunteer profile if applicable
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  // For development environment only - in production we use Cognito
  static async create(data) {
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(data.password, salt);

    const user = new User({
      ...data,
      password: hashedPassword
    });

    // In production, we would store users in Cognito
    // For development, we create a simulated user
    return user;
  }

  // Generate JWT token
  static generateToken(user) {
    return jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      ENV.JWT_SECRET,
      { expiresIn: ENV.JWT_EXPIRES_IN }
    );
  }

  // Verify password
  static async verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }
}

/*****************************************************************************
 * SERVICE FUNCTIONS
 *****************************************************************************/

/**
 * Email Service
 */
const emailService = {
  // Template cache for email templates
  templateCache: {},

  // Load email template
  loadTemplate: function(templateName) {
    if (this.templateCache[templateName]) {
      return this.templateCache[templateName];
    }
    
    // In production, templates would be loaded from a templates directory
    // For this single file implementation, we'll define them inline
    const templates = {
      welcome: `
        <html>
          <body>
            <h1>Welcome to STL Tornado Relief</h1>
            <p>Hello {{firstName}} {{lastName}},</p>
            <p>Thank you for registering as a volunteer to help with the tornado relief efforts in St. Louis.</p>
            <p>Your help is greatly appreciated, and we'll be in touch with task assignments soon.</p>
            <p>For urgent needs, please call our hotline at 555-123-4567.</p>
          </body>
        </html>
      `,
      taskAssignment: `
        <html>
          <body>
            <h1>Task Assignment</h1>
            <p>Hello {{volunteerName}},</p>
            <p>You have been assigned to a new task:</p>
            <h2>{{taskTitle}}</h2>
            <p><strong>Location:</strong> {{taskLocation}}</p>
            <p><strong>Date:</strong> {{taskDate}}</p>
            <p>Please check your volunteer dashboard for more details.</p>
            <p>Thank you for your service!</p>
          </body>
        </html>
      `
    };
    
    const templateSource = templates[templateName] || '<p>Template not found</p>';
    const template = Handlebars.compile(templateSource);
    
    this.templateCache[templateName] = template;
    return template;
  },

  // Send email
  sendEmail: async function({ to, subject, template, data }) {
    try {
      const compiledTemplate = this.loadTemplate(template);
      const htmlBody = compiledTemplate(data);
      
      const params = {
        Source: ENV.EMAIL_FROM,
        Destination: {
          ToAddresses: Array.isArray(to) ? to : [to]
        },
        Message: {
          Subject: {
            Data: subject
          },
          Body: {
            Html: {
              Data: htmlBody
            }
          }
        }
      };
      
      await ses.sendEmail(params).promise();
      return true;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
};

/**
 * SMS Service
 */
const smsService = {
  // Send SMS
  sendSMS: async function({ to, message }) {
    try {
      const params = {
        PhoneNumber: to,
        Message: message,
        MessageAttributes: {
          'AWS.SNS.SMS.SenderID': {
            DataType: 'String',
            StringValue: 'STLRELIEF'
          },
          'AWS.SNS.SMS.SMSType': {
            DataType: 'String',
            StringValue: 'Transactional'
          }
        }
      };
      
      await sns.publish(params).promise();
      return true;
    } catch (error) {
      console.error('Error sending SMS:', error);
      throw error;
    }
  }
};

/**
 * File Upload Service
 */
const fileService = {
  // Upload file to S3
  uploadFile: async function(file, folder = 'uploads') {
    try {
      const fileName = `${folder}/${Date.now()}-${file.originalname}`;
      
      const params = {
        Bucket: ENV.S3_BUCKET,
        Key: fileName,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'public-read'
      };
      
      const result = await s3.upload(params).promise();
      return {
        url: result.Location,
        key: result.Key
      };
    } catch (error) {
      console.error('Error uploading file:', error);
      throw error;
    }
  },
  
  // Get file from S3
  getFileUrl: function(key) {
    return `https://${ENV.S3_BUCKET}.s3.amazonaws.com/${key}`;
  }
};

/**
 * Matching Service to find the best volunteers for a task
 */
const matchingService = {
  // Find matching volunteers for a task based on skills and availability
  findMatchingVolunteers: async function(taskId) {
    try {
      const task = await Task.findById(taskId);
      if (!task) {
        throw new Error('Task not found');
      }
      
      // Get all active volunteers
      const allVolunteers = await Volunteer.list({ status: 'active' });
      
      // Filter volunteers by required skills
      let matchingVolunteers = allVolunteers;
      if (task.requiredSkills && task.requiredSkills.length > 0) {
        matchingVolunteers = allVolunteers.filter(volunteer => {
          return task.requiredSkills.some(skill => 
            volunteer.skills && volunteer.skills.includes(skill)
          );
        });
      }
      
      // Filter by availability if task has a start date
      if (task.startDate) {
        const taskDate = new Date(task.startDate);
        const taskDay = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'][taskDate.getDay()];
        
        matchingVolunteers = matchingVolunteers.filter(volunteer => {
          if (!volunteer.availability) return false;
          
          return volunteer.availability[taskDay] === true;
        });
      }
      
      // Sort by skill match count (most matching skills first)
      matchingVolunteers.sort((a, b) => {
        const aMatchCount = task.requiredSkills ? task.requiredSkills.filter(skill => 
          a.skills && a.skills.includes(skill)
        ).length : 0;
        
        const bMatchCount = task.requiredSkills ? task.requiredSkills.filter(skill => 
          b.skills && b.skills.includes(skill)
        ).length : 0;
        
        return bMatchCount - aMatchCount;
      });
      
      return matchingVolunteers;
    } catch (error) {
      console.error('Error finding matching volunteers:', error);
      throw error;
    }
  }
};

/*****************************************************************************
 * MIDDLEWARE
 *****************************************************************************/

/**
 * Authentication Middleware
 */
const authMiddleware = {
  // Authenticate user
  authenticate: async function(req, res, next) {
    try {
      // Get token from header
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return next(new AppError('Authentication required', 401));
      }

      // In production, verify token with Cognito
      if (ENV.NODE_ENV === 'production' && ENV.COGNITO_USER_POOL_ID) {
        try {
          const params = {
            AccessToken: token
          };
          
          const userData = await cognitoISP.getUser(params).promise();
          
          // Extract user information
          const user = {
            id: userData.Username,
            email: userData.UserAttributes.find(attr => attr.Name === 'email')?.Value,
            role: userData.UserAttributes.find(attr => attr.Name === 'custom:role')?.Value || 'volunteer'
          };
          
          req.user = user;
          return next();
        } catch (error) {
          return next(new AppError('Invalid token', 401));
        }
      } else {
        // In development, use simple JWT
        const decoded = jwt.verify(token, ENV.JWT_SECRET);
        req.user = decoded;
        next();
      }
    } catch (error) {
      next(new AppError('Authentication failed', 401));
    }
  },

  // Authorize by role
  authorize: function(roles) {
    return (req, res, next) => {
      if (!req.user) {
        return next(new AppError('Authentication required', 401));
      }
      
      if (!roles.includes(req.user.role)) {
        return next(new AppError('You do not have permission to perform this action', 403));
      }
      
      next();
    };
  }
};

/*****************************************************************************
 * CONTROLLERS
 *****************************************************************************/

/**
 * Volunteer Controller
 */
const volunteerController = {
  // Register new volunteer
  register: catchAsync(async (req, res) => {
    // Check if volunteer already exists
    const existingVolunteer = await Volunteer.findByEmail(req.body.email);
    if (existingVolunteer) {
      return res.status(400).json({ error: 'Email already registered' });
    }
  
    // Create new volunteer
    const volunteer = await Volunteer.create(req.body);
    
    // Send welcome email
    await emailService.sendEmail({
      to: volunteer.email,
      subject: 'Welcome to STL Tornado Relief',
      template: 'welcome',
      data: {
        firstName: volunteer.firstName,
        lastName: volunteer.lastName
      }
    });
  
    res.status(201).json(volunteer);
  }),
  
  // Get volunteer by ID
  getVolunteer: catchAsync(async (req, res) => {
    const volunteer = await Volunteer.findById(req.params.id);
    if (!volunteer) {
      return res.status(404).json({ error: 'Volunteer not found' });
    }
    res.json(volunteer);
  }),
  
  // Update volunteer
  updateVolunteer: catchAsync(async (req, res) => {
    const updatedVolunteer = await Volunteer.update(req.params.id, req.body);
    if (!updatedVolunteer) {
      return res.status(404).json({ error: 'Volunteer not found' });
    }
    res.json(updatedVolunteer);
  }),
  
  // List volunteers with optional filters
  listVolunteers: catchAsync(async (req, res) => {
    const filters = {};
    
    // Apply filters from query params
    if (req.query.skills) {
      filters.skills = req.query.skills.split(',');
    }
    if (req.query.status) {
      filters.status = req.query.status;
    }
    if (req.query.location) {
      filters.location = req.query.location;
    }
  
    const volunteers = await Volunteer.list(filters);
    res.json(volunteers);
  })
};

/**
 * Task Controller
 */
const taskController = {
  // Create new task
  createTask: catchAsync(async (req, res) => {
    const task = await Task.create({
      ...req.body,
      createdBy: req.user.id
    });
    
    res.status(201).json(task);
  }),
  
  // Get task by ID
  getTask: catchAsync(async (req, res) => {
    const task = await Task.findById(req.params.id);
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json(task);
  }),
  
  // Update task
  updateTask: catchAsync(async (req, res) => {
    const updatedTask = await Task.update(req.params.id, req.body);
    if (!updatedTask) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json(updatedTask);
  }),
  
  // List tasks with optional filters
  listTasks: catchAsync(async (req, res) => {
    const filters = {};
    
    // Apply filters from query params
    if (req.query.status) {
      filters.status = req.query.status;
    }
    if (req.query.priority) {
      filters.priority = req.query.priority;
    }
    if (req.query.location) {
      filters.location = req.query.location;
    }
    if (req.query.startDate) {
      filters.startDate = req.query.startDate;
    }
    if (req.query.endDate) {
      filters.endDate = req.query.endDate;
    }
  
    const tasks = await Task.list(filters);
    res.json(tasks);
  }),
  
  // Assign volunteers to a task
  assignVolunteers: catchAsync(async (req, res) => {
    const { taskId } = req.params;
    const { volunteerIds } = req.body;
    
    const task = await Task.assignVolunteers(taskId, volunteerIds);
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // Notify assigned volunteers
    for (const volunteerId of volunteerIds) {
      const volunteer = await Volunteer.findById(volunteerId);
      if (volunteer) {
        // Send email notification
        await emailService.sendEmail({
          to: volunteer.email,
          subject: 'You have been assigned to a task',
          template: 'taskAssignment',
          data: {
            volunteerName: `${volunteer.firstName} ${volunteer.lastName}`,
            taskTitle: task.title,
            taskLocation: task.location,
            taskDate: task.startDate
          }
        });
        
        // Send SMS notification if phone is available
        if (volunteer.phone) {
          await smsService.sendSMS({
            to: volunteer.phone,
            message: `You've been assigned to "${task.title}" at ${task.location} on ${new Date(task.startDate).toLocaleDateString()}. Please check your email for details.`
          });
        }
      }
    }
    
    res.json(task);
  }),

  // Find matching volunteers for a task
  findMatches: catchAsync(async (req, res) => {
    const { taskId } = req.params;
    const matchingVolunteers = await matchingService.findMatchingVolunteers(taskId);
    res.json(matchingVolunteers);
  })
};

/**
 * Resource Controller
 */
const resourceController = {
  // Create new resource
  createResource: catchAsync(async (req, res) => {
    const resource = await Resource.create(req.body);
    res.status(201).json(resource);
  }),
  
  // Get resource by ID
  getResource: catchAsync(async (req, res) => {
    const resource = await Resource.findById(req.params.id);
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    res.json(resource);
  }),
  
  // Update resource
  updateResource: catchAsync(async (req, res) => {
    const updatedResource = await Resource.update(req.params.id, req.body);
    if (!updatedResource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    res.json(updatedResource);
  }),
  
  // List resources with optional filters
  listResources: catchAsync(async (req, res) => {
    const filters = {};
    
    // Apply filters from query params
    if (req.query.type) {
      filters.type = req.query.type;
    }
    if (req.query.status) {
      filters.status = req.query.status;
    }
    if (req.query.location) {
      filters.location = req.query.location;
    }
  
    const resources = await Resource.list(filters);
    res.json(resources);
  }),
  
  // Adjust resource quantity
  adjustQuantity: catchAsync(async (req, res) => {
    const { id } = req.params;
    const { adjustment } = req.body;
    
    if (typeof adjustment !== 'number') {
      return res.status(400).json({ error: 'Adjustment must be a number' });
    }
    
    const resource = await Resource.adjustQuantity(id, adjustment);
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    res.json(resource);
  })
};

/**
 * Auth Controller
 */
const authController = {
  // Register user (development only - in production use Cognito)
  register: catchAsync(async (req, res) => {
    if (ENV.NODE_ENV === 'production' && ENV.COGNITO_USER_POOL_ID) {
      return res.status(400).json({
        error: 'Registration is handled by Cognito in production'
      });
    }

    const { email, password, firstName, lastName, role } = req.body;
    
    // Create user
    const user = await User.create({
      email,
      password,
      firstName,
      lastName,
      role: role || 'volunteer'
    });
    
    // Generate token
    const token = User.generateToken(user);
    
    // Return user info and token
    res.status(201).json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      token
    });
  }),
  
  // Login user (development only - in production use Cognito)
  login: catchAsync(async (req, res) => {
    if (ENV.NODE_ENV === 'production' && ENV.COGNITO_USER_POOL_ID) {
      return res.status(400).json({
        error: 'Login is handled by Cognito in production'
      });
    }

    const { email, password } = req.body;
    
    // For development demo only - in production we would use Cognito
    // In a real application, we would verify credentials against a user database
    // This is a simple example for development purposes
    const demoUsers = [
      {
        id: 'admin-user',
        email: 'admin@example.com',
        password: '$2a$10$GcQS8NQ1e0VCJ9TXkzgAieuOKjAGR9Ai3TAe1VAFS2ExRYTxYtMfK', // password: admin123
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin'
      },
      {
        id: 'coordinator-user',
        email: 'coordinator@example.com',
        password: '$2a$10$GcQS8NQ1e0VCJ9TXkzgAieuOKjAGR9Ai3TAe1VAFS2ExRYTxYtMfK', // password: admin123
        firstName: 'Coordinator',
        lastName: 'User',
        role: 'coordinator'
      },
      {
        id: 'volunteer-user',
        email: 'volunteer@example.com',
        password: '$2a$10$GcQS8NQ1e0VCJ9TXkzgAieuOKjAGR9Ai3TAe1VAFS2ExRYTxYtMfK', // password: admin123
        firstName: 'Volunteer',
        lastName: 'User',
        role: 'volunteer'
      }
    ];
    
    // Find user by email
    const user = demoUsers.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isPasswordValid = await User.verifyPassword(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = User.generateToken(user);
    
    // Return user info and token
    res.json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      token
    });
  }),
  
  // Get current user
  getCurrentUser: catchAsync(async (req, res) => {
    // User object was attached by authenticate middleware
    res.json(req.user);
  })
};

/*****************************************************************************
 * ROUTES
 *****************************************************************************/

// Create Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// API Routes
const apiRouter = express.Router();

// Volunteer routes
apiRouter.post('/volunteers', volunteerController.register);
apiRouter.get('/volunteers', authMiddleware.authenticate, volunteerController.listVolunteers);
apiRouter.get('/volunteers/:id', authMiddleware.authenticate, volunteerController.getVolunteer);
apiRouter.put('/volunteers/:id', authMiddleware.authenticate, volunteerController.updateVolunteer);

// Task routes
apiRouter.post('/tasks', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), taskController.createTask);
apiRouter.get('/tasks', authMiddleware.authenticate, taskController.listTasks);
apiRouter.get('/tasks/:id', authMiddleware.authenticate, taskController.getTask);
apiRouter.put('/tasks/:id', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), taskController.updateTask);
apiRouter.post('/tasks/:taskId/assign', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), taskController.assignVolunteers);
apiRouter.get('/tasks/:taskId/matches', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), taskController.findMatches);

// Resource routes
apiRouter.post('/resources', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), resourceController.createResource);
apiRouter.get('/resources', authMiddleware.authenticate, resourceController.listResources);
apiRouter.get('/resources/:id', authMiddleware.authenticate, resourceController.getResource);
apiRouter.put('/resources/:id', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), resourceController.updateResource);
apiRouter.post('/resources/:id/adjust', authMiddleware.authenticate, authMiddleware.authorize(['admin', 'coordinator']), resourceController.adjustQuantity);

// Auth routes
apiRouter.post('/auth/register', authController.register);
apiRouter.post('/auth/login', authController.login);
apiRouter.get('/auth/me', authMiddleware.authenticate, authController.getCurrentUser);

// Mount API router
app.use('/api', apiRouter);

// Serve static files from the React app in production
if (ENV.NODE_ENV === 'production') {
  // Serve React static files
  app.use(express.static(path.join(__dirname, 'public')));
  
  // For any request that doesn't match an API route, send the React app
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Error handling middleware
app.use(errorHandler);

// Server setup
if (ENV.NODE_ENV !== 'production') {
  // In development, run Express server
  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
}

// Export for Lambda
module.exports.handler = serverless(app);

/*****************************************************************************
 * DATABASE INITIALIZATION
 *****************************************************************************/

/**
 * Create DynamoDB tables if they don't exist
 * This is typically done as part of the CloudFormation/Serverless deployment
 * but included here for completeness
 */
async function initializeTables() {
  const dynamoClient = new AWS.DynamoDB();
  
  try {
    // Volunteers table
    await dynamoClient.createTable({
      TableName: ENV.VOLUNTEERS_TABLE,
      KeySchema: [
        { AttributeName: 'id', KeyType: 'HASH' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'id', AttributeType: 'S' },
        { AttributeName: 'email', AttributeType: 'S' }
      ],
      GlobalSecondaryIndexes: [
        {
          IndexName: 'EmailIndex',
          KeySchema: [
            { AttributeName: 'email', KeyType: 'HASH' }
          ],
          Projection: {
            ProjectionType: 'ALL'
          },
          ProvisionedThroughput: {
            ReadCapacityUnits: 5,
            WriteCapacityUnits: 5
          }
        }
      ],
      ProvisionedThroughput: {
        ReadCapacityUnits: 5,
        WriteCapacityUnits: 5
      }
    }).promise();
    
    // Tasks table
    await dynamoClient.createTable({
      TableName: ENV.TASKS_TABLE,
      KeySchema: [
        { AttributeName: 'id', KeyType: 'HASH' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'id', AttributeType: 'S' },
        { AttributeName: 'status', AttributeType: 'S' },
        { AttributeName: 'createdAt', AttributeType: 'S' }
      ],
      GlobalSecondaryIndexes: [
        {
          IndexName: 'StatusCreatedAtIndex',
          KeySchema: [
            { AttributeName: 'status', KeyType: 'HASH' },
            { AttributeName: 'createdAt', KeyType: 'RANGE' }
          ],
          Projection: {
            ProjectionType: 'ALL'
          },
          ProvisionedThroughput: {
            ReadCapacityUnits: 5,
            WriteCapacityUnits: 5
          }
        }
      ],
      ProvisionedThroughput: {
        ReadCapacityUnits: 5,
        WriteCapacityUnits: 5
      }
    }).promise();
    
    // Resources table
    await dynamoClient.createTable({
      TableName: ENV.RESOURCES_TABLE,
      KeySchema: [
        { AttributeName: 'id', KeyType: 'HASH' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'id', AttributeType: 'S' },
        { AttributeName: 'type', AttributeType: 'S' }
      ],
      GlobalSecondaryIndexes: [
        {
          IndexName: 'TypeIndex',
          KeySchema: [
            { AttributeName: 'type', KeyType: 'HASH' }
          ],
          Projection: {
            ProjectionType: 'ALL'
          },
          ProvisionedThroughput: {
            ReadCapacityUnits: 5,
            WriteCapacityUnits: 5
          }
        }
      ],
      ProvisionedThroughput: {
        ReadCapacityUnits: 5,
        WriteCapacityUnits: 5
      }
    }).promise();
    
    console.log('Tables created successfully');
  } catch (error) {
    // Table likely already exists or there was a permission issue
    console.error('Error creating tables:', error);
  }
}

// Initialize tables in development environment
if (ENV.NODE_ENV === 'development') {
  initializeTables().catch(console.error);
}

/*****************************************************************************
 * AWS CLOUDFORMATION TEMPLATE EXPORT
 *****************************************************************************/

/**
 * CloudFormation template for AWS deployment
 * This would typically be in a separate YAML or JSON file
 * But included here for completeness in a single-file solution
 */
const cloudFormationTemplate = {
  AWSTemplateFormatVersion: '2010-09-09',
  Description: 'STL Tornado Relief - Volunteer Management System',
  
  Parameters: {
    Environment: {
      Type: 'String',
      Default: 'dev',
      AllowedValues: ['dev', 'staging', 'prod'],
      Description: 'Environment (dev, staging, prod)'
    }
  },
  
  Resources: {
    // DynamoDB Tables
    VolunteersTable: {
      Type: 'AWS::DynamoDB::Table',
      Properties: {
        TableName: { 'Fn::Join': ['-', ['StlReliefVolunteers', { Ref: 'Environment' }]] },
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
          { AttributeName: 'id', AttributeType: 'S' },
          { AttributeName: 'email', AttributeType: 'S' }
        ],
        KeySchema: [
          { AttributeName: 'id', KeyType: 'HASH' }
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'EmailIndex',
            KeySchema: [
              { AttributeName: 'email', KeyType: 'HASH' }
            ],
            Projection: {
              ProjectionType: 'ALL'
            }
          }
        ]
      }
    },
    
    TasksTable: {
      Type: 'AWS::DynamoDB::Table',
      Properties: {
        TableName: { 'Fn::Join': ['-', ['StlReliefTasks', { Ref: 'Environment' }]] },
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
          { AttributeName: 'id', AttributeType: 'S' },
          { AttributeName: 'status', AttributeType: 'S' },
          { AttributeName: 'createdAt', AttributeType: 'S' }
        ],
        KeySchema: [
          { AttributeName: 'id', KeyType: 'HASH' }
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'StatusCreatedAtIndex',
            KeySchema: [
              { AttributeName: 'status', KeyType: 'HASH' },
              { AttributeName: 'createdAt', KeyType: 'RANGE' }
            ],
            Projection: {
              ProjectionType: 'ALL'
            }
          }
        ]
      }
    },
    
    ResourcesTable: {
      Type: 'AWS::DynamoDB::Table',
      Properties: {
        TableName: { 'Fn::Join': ['-', ['StlReliefResources', { Ref: 'Environment' }]] },
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
          { AttributeName: 'id', AttributeType: 'S' },
          { AttributeName: 'type', AttributeType: 'S' }
        ],
        KeySchema: [
          { AttributeName: 'id', KeyType: 'HASH' }
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'TypeIndex',
            KeySchema: [
              { AttributeName: 'type', KeyType: 'HASH' }
            ],
            Projection: {
              ProjectionType: 'ALL'
            }
          }
        ]
      }
    },
    
    // S3 Bucket for file uploads
    UploadsBucket: {
      Type: 'AWS::S3::Bucket',
      Properties: {
        BucketName: { 'Fn::Join': ['-', ['stl-tornado-relief-uploads', { Ref: 'Environment' }]] },
        CorsConfiguration: {
          CorsRules: [
            {
              AllowedHeaders: ['*'],
              AllowedMethods: ['GET', 'PUT', 'POST', 'DELETE', 'HEAD'],
              AllowedOrigins: ['*'],
              MaxAge: 3000
            }
          ]
        }
      }
    },
    
    // Cognito User Pool
    UserPool: {
      Type: 'AWS::Cognito::UserPool',
      Properties: {
        UserPoolName: { 'Fn::Join': ['-', ['stl-relief-users', { Ref: 'Environment' }]] },
        AutoVerifiedAttributes: ['email'],
        Schema: [
          {
            Name: 'email',
            Required: true,
            Mutable: true
          },
          {
            Name: 'custom:role',
            AttributeDataType: 'String',
            Mutable: true
          }
        ]
      }
    },
    
    // Cognito User Pool Client
    UserPoolClient: {
      Type: 'AWS::Cognito::UserPoolClient',
      Properties: {
        ClientName: { 'Fn::Join': ['-', ['stl-relief-client', { Ref: 'Environment' }]] },
        UserPoolId: { Ref: 'UserPool' },
        GenerateSecret: false,
        ExplicitAuthFlows: [
          'ALLOW_USER_PASSWORD_AUTH',
          'ALLOW_REFRESH_TOKEN_AUTH'
        ]
      }
    },
    
    // Lambda function
    LambdaFunction: {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: { 'Fn::Join': ['-', ['stl-relief-api', { Ref: 'Environment' }]] },
        Handler: 'index.handler',
        Role: { 'Fn::GetAtt': ['LambdaExecutionRole', 'Arn'] },
        Code: {
          S3Bucket: { Ref: 'DeploymentBucket' },
          S3Key: 'lambda-deployment.zip'
        },
        Runtime: 'nodejs16.x',
        Timeout: 30,
        MemorySize: 512,
        Environment: {
          Variables: {
            NODE_ENV: { Ref: 'Environment' },
            DYNAMODB_VOLUNTEERS_TABLE: { Ref: 'VolunteersTable' },
            DYNAMODB_TASKS_TABLE: { Ref: 'TasksTable' },
            DYNAMODB_RESOURCES_TABLE: { Ref: 'ResourcesTable' },
            COGNITO_USER_POOL_ID: { Ref: 'UserPool' },
            COGNITO_APP_CLIENT_ID: { Ref: 'UserPoolClient' },
            S3_BUCKET: { Ref: 'UploadsBucket' }
          }
        }
      }
    },
    
    // Lambda execution role
    LambdaExecutionRole: {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: ['lambda.amazonaws.com']
              },
              Action: ['sts:AssumeRole']
            }
          ]
        },
        ManagedPolicyArns: [
          'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        ],
        Policies: [
          {
            PolicyName: 'stl-relief-lambda-policy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: [
                    'dynamodb:GetItem',
                    'dynamodb:PutItem',
                    'dynamodb:UpdateItem',
                    'dynamodb:DeleteItem',
                    'dynamodb:Query',
                    'dynamodb:Scan'
                  ],
                  Resource: [
                    { 'Fn::GetAtt': ['VolunteersTable', 'Arn'] },
                    { 'Fn::GetAtt': ['TasksTable', 'Arn'] },
                    { 'Fn::GetAtt': ['ResourcesTable', 'Arn'] },
                    { 'Fn::Join': ['/', [{ 'Fn::GetAtt': ['VolunteersTable', 'Arn'] }, 'index', '*']] },
                    { 'Fn::Join': ['/', [{ 'Fn::GetAtt': ['TasksTable', 'Arn'] }, 'index', '*']] },
                    { 'Fn::Join': ['/', [{ 'Fn::GetAtt': ['ResourcesTable', 'Arn'] }, 'index', '*']] }
                  ]
                },
                {
                  Effect: 'Allow',
                  Action: [
                    's3:GetObject',
                    's3:PutObject',
                    's3:DeleteObject'
                  ],
                  Resource: [
                    { 'Fn::Join': ['', ['arn:aws:s3:::', { Ref: 'UploadsBucket' }, '/*']] }
                  ]
                },
                {
                  Effect: 'Allow',
                  Action: [
                    'ses:SendEmail',
                    'ses:SendRawEmail'
                  ],
                  Resource: '*'
                },
                {
                  Effect: 'Allow',
                  Action: [
                    'sns:Publish'
                  ],
                  Resource: '*'
                },
                {
                  Effect: 'Allow',
                  Action: [
                    'cognito-idp:AdminCreateUser',
                    'cognito-idp:AdminGetUser',
                    'cognito-idp:AdminInitiateAuth',
                    'cognito-idp:AdminUpdateUserAttributes'
                  ],
                  Resource: { 'Fn::GetAtt': ['UserPool', 'Arn'] }
                }
              ]
            }
          }
        ]
      }
    },
    
    // API Gateway
    ApiGateway: {
      Type: 'AWS::ApiGateway::RestApi',
      Properties: {
        Name: { 'Fn::Join': ['-', ['stl-relief-api', { Ref: 'Environment' }]] },
        Description: 'API for STL Tornado Relief Volunteer Management System'
      }
    },
    
    // API Gateway deployment
    ApiGatewayDeployment: {
      Type: 'AWS::ApiGateway::Deployment',
      DependsOn: ['ApiGatewayProxyMethod'],
      Properties: {
        RestApiId: { Ref: 'ApiGateway' },
        StageName: { Ref: 'Environment' }
      }
    },
    
    // API Gateway resource
    ApiGatewayResource: {
      Type: 'AWS::ApiGateway::Resource',
      Properties: {
        RestApiId: { Ref: 'ApiGateway' },
        ParentId: { 'Fn::GetAtt': ['ApiGateway', 'RootResourceId'] },
        PathPart: '{proxy+}'
      }
    },
    
    // API Gateway method
    ApiGatewayProxyMethod: {
      Type: 'AWS::ApiGateway::Method',
      Properties: {
        RestApiId: { Ref: 'ApiGateway' },
        ResourceId: { Ref: 'ApiGatewayResource' },
        HttpMethod: 'ANY',
        AuthorizationType: 'NONE',
        Integration: {
          Type: 'AWS_PROXY',
          IntegrationHttpMethod: 'POST',
          Uri: { 'Fn::Join': ['', ['arn:aws:apigateway:', { Ref: 'AWS::Region' }, ':lambda:path/2015-03-31/functions/', { 'Fn::GetAtt': ['LambdaFunction', 'Arn'] }, '/invocations']] }
        }
      }
    },
    
    // Lambda permission
    LambdaPermission: {
      Type: 'AWS::Lambda::Permission',
      Properties: {
        Action: 'lambda:InvokeFunction',
        FunctionName: { Ref: 'LambdaFunction' },
        Principal: 'apigateway.amazonaws.com',
        SourceArn: { 'Fn::Join': ['', ['arn:aws:execute-api:', { Ref: 'AWS::Region' }, ':', { Ref: 'AWS::AccountId' }, ':', { Ref: 'ApiGateway' }, '/', { Ref: 'Environment' }, '/*/*']] }
      }
    }
  },
  
  Outputs: {
    ApiEndpoint: {
      Description: 'API Gateway endpoint URL',
      Value: { 'Fn::Join': ['', ['https://', { Ref: 'ApiGateway' }, '.execute-api.', { Ref: 'AWS::Region' }, '.amazonaws.com/', { Ref: 'Environment' }]] }
    },
    UserPoolId: {
      Description: 'Cognito User Pool ID',
      Value: { Ref: 'UserPool' }
    },
    UserPoolClientId: {
      Description: 'Cognito User Pool Client ID',
      Value: { Ref: 'UserPoolClient' }
    },
    UploadsBucketName: {
      Description: 'S3 bucket for file uploads',
      Value: { Ref: 'UploadsBucket' }
    }
  }
};

// Export CloudFormation template
// This would typically be written to a file, but we include it as a commented JSON for completeness
/*
const cloudFormationTemplateJson = JSON.stringify(cloudFormationTemplate, null, 2);
*/

/*****************************************************************************
 * DEPLOYMENT INSTRUCTIONS
 *****************************************************************************/

/*
# Deploying to AWS

## Prerequisites
1. AWS CLI installed and configured with appropriate permissions
2. Node.js and npm installed
3. Serverless Framework installed (npm install -g serverless)

## Deployment Steps

### 1. Create a deployment package
zip -r deployment.zip . -x "node_modules/*" "*.git*"

### 2. Create an S3 bucket for deployment artifacts
aws s3 mb s3://stl-tornado-relief-deployment

### 3. Upload the deployment package
aws s3 cp deployment.zip s3://stl-tornado-relief-deployment/

### 4. Deploy using CloudFormation
aws cloudformation create-stack \
  --stack-name stl-tornado-relief \
  --template-body file://cloudformation-template.json \
  --capabilities CAPABILITY_IAM \
  --parameters ParameterKey=Environment,ParameterValue=prod \
               ParameterKey=DeploymentBucket,ParameterValue=stl-tornado-relief-deployment

### 5. Alternative: Deploy using Serverless Framework
serverless deploy --stage prod
*/
