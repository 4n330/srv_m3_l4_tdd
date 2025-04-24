var express = require('express');
var router = express.Router();
const { isAuth } = require('../middleware/isAuth');
const db = require('../models');
const BookmarkService = require('../services/BookmarkService');
const bookmarkService = new BookmarkService(db);

/* GET home page. */
router.get('/', isAuth, async (req, res, next) => {});

router.post('/', isAuth, async (req, res, next) => {
  try {
    const { Name, URL } = req.body;
bookmarkService.create(Name, URL, req.user.id).then((bookmark) => {
      res.status(201).send({message: 'Bookmark created successfully'})
    });

} catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
  