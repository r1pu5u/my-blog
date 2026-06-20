import { getCollection } from 'astro:content';

export interface BlogPost {
  slug: string;
  title: string;
  date: string;
  year: string;
  month: string;
  category: string;
  tags: string[];
  excerpt: string;
  thumbnail: string;
}

export async function getBlogPosts(): Promise<BlogPost[]> {
  const posts = await getCollection('blog');

  return posts
    .map((post) => {
      const [year, month] = post.data.date.split('-');
      return {
        slug: post.id,
        title: post.data.title,
        date: post.data.date,
        year,
        month,
        category: post.data.category,
        tags: post.data.tags,
        excerpt: post.data.excerpt,
        thumbnail: post.data.thumbnail,
      };
    })
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
}

// For backward compatibility with static imports
export const blogPostsPromise = getBlogPosts();
