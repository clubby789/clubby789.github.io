---
layout: default
---


## Recent posts feed
<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
	<span><p>{{ post.excerpt }}</p> <img src="/assets/{{post.image}}" alt="Writeup" style="width:200px;"> </span>
    </li>
  {% endfor %}
</ul>

## Who am I?
A teenager from the UK who's very interested in computing, cybersecurity and CTFs.

## What is this site?
A blog where I'll be posting projects I'm working on, HackTheBox writeups, and anything else I find interesting.

### Profiles:
[Twitter](https://twitter.com/clubby789)

[GitHub](https://github.com/clubby789) <- You are here!

[![clubby789](https://www.hackthebox.eu/badge/image/83743)](https://www.hackthebox.eu/home/users/profile/83743)

