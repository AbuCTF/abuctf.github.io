Stash of security related stuff. Peace!

```
Author: Abu [H7Tex]
```

Steps to run to locally [in case of blackout]

- Install Git
- Install Ruby

Verify that both `git` and `ruby` is installed with `-v` flag [duh]
```
gem install bundler
gem install jekyll
```
Install Project Dependencies: Inside the project folder (where the Gemfile is), run:

`bundle install`

Serve the Site: Now you can run the Jekyll server using:

`bundle exec jekyll serve --incremental`

This command will build and serve your Jekyll site locally. By default, it should be available at http://127.0.0.1:4000/ on your browser.
