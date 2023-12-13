#!/usr/bin/env bash
## This script compile the markdown posts to html blog posts
### There are definitely better ways to do this, but it's simpler I think
# sudo apt install pandoc

cd "$(dirname $0)"

PWD=$(pwd)
POSTS_DIR=$PWD/posts
POSTS_DIR_PT_BR=$PWD/posts/pt-br
BLOG_HTML_DIR=$PWD/web/blog
BLOG_HTML_DIR_PT_BR=$PWD/web/pt-br/blog

for post in $POSTS_DIR/*.md; do
  outfile="$BLOG_HTML_DIR/$(basename $post | sed 's/\.md/.html/g')"
  echo "[+] $(basename $post) -> $(basename $outfile)"
  pandoc $post -o /tmp/post.html
  
  cat "$PWD/web/assets/blog/header.html" /tmp/post.html "$PWD/web/assets/blog/footer.html" > $outfile
done

for post in $POSTS_DIR_PT_BR/*.md; do
  outfile="$BLOG_HTML_DIR_PT_BR/$(basename $post | sed 's/\.md/.html/g')"
  echo "[+] $(basename $post) -> $(basename $outfile)"
  pandoc $post -o /tmp/post.html
  
  cat "$PWD/web/assets/blog/header.html" /tmp/post.html "$PWD/web/assets/blog/footer.html" > $outfile
done

rm -rf /tmp/post.html
