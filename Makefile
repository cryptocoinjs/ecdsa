test: node-test browser-test

node-test:
	@./node_modules/.bin/mocha 

browser-test:
	@./node_modules/.bin/mochify --wd -R spec --timeout 20000

.PHONY: node-test browser-test