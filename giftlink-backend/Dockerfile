FROM node:18

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

ENV MONGO_URI=mongodb://mongodb-service:27017
ENV JWT_SECRET=your_jwt_secret

EXPOSE 3060

CMD ["node", "app.js"]
