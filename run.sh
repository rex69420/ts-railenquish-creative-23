#!/bin/bash

npm i
npm run build
gunicorn -w 4 -b 0.0.0.0:4646 app:app