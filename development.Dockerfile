FROM node:21-bullseye-slim AS dependencies

WORKDIR /dependencies

# Install dependencies first so rebuild of these layers is only needed when dependencies change
COPY package.json yarn.lock auth0-mdl-v0.3.0-wwwallet-build-1724387059.tgz .
RUN --mount=type=secret,id=npmrc,required=true,target=./.npmrc,uid=1000 \
	yarn cache clean -f && yarn install


FROM node:21-bullseye-slim AS development

ENV NODE_PATH=/node_modules
COPY --from=dependencies /dependencies/node_modules /node_modules

WORKDIR /app
ENV NODE_ENV development
CMD [ "yarn", "start-docker" ]

# src/ and public/ will be mounted from host, but we need some config files in the image for startup
COPY . .

# Set user last so everything is readonly by default
USER node
