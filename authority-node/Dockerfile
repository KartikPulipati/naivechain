FROM node:18
WORKDIR /authority-node
COPY package.json ./
COPY authority.js ./
RUN npm install
EXPOSE 4000
CMD [ "node", "authority.js" ]
