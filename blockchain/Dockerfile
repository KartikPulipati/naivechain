FROM node:14

# Set working directory
WORKDIR /naivechain/blockchain

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy the rest of your app (main.js, etc.)
COPY main.js ./

# Expose HTTP and P2P ports
EXPOSE 3001
EXPOSE 6001

# Start the app, passing PEERS env variable if set
CMD ["npm", "start"]
