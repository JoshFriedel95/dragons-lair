const bcrypt = require('bcryptjs')

module.exports = {
    register: async(req,res) => {
        const db = req.app.get('db')
        const {username, password, isAdmin} = req.body
        const [existingUser] = await db.get_user([username])

        if(existingUser){
            return res.status(409).send('Username taken')
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const [registeredUser] = await db.register_user([isAdmin, username, hash])
        req.session.user = {
            isAdmin: registeredUser.is_admin,
            id: registeredUser.id,
            username: registeredUser.username
        }
        res.status(201).send(registeredUser)
     },
     login: async(req,res) => {
         const db =req.app.get('db')
         const {username, password} = req.body
         const [existingUser] = await db.get_user([username])

         if(!existingUser){
             return res.status(401).send('User not found')
         }
         const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)
         if(!isAuthenticated){
             return res.status(403).send('Incorrect password')
         }
         delete existingUser.hash
         req.session.user = {
             isAdmin: existingUser.is_admin,
             id: existingUser.id,
             username: existingUser.username
         }
         res.status(200).send(existingUser)

     },
     logout: (req,res) => {
        req.session.destroy()
        res.sendStatus(200)
     }
}