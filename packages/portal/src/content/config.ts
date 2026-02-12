import { defineCollection, z } from 'astro:content';

const docsCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    order: z.number().default(999),
    category: z
      .enum([
        'Getting Started',
        'Architecture',
        'Security',
        'Operations',
        'Development',
        'Reference',
      ])
      .default('Reference'),
  }),
});

const blogCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.date(),
    author: z.string().default('zk-id Team'),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

export const collections = {
  docs: docsCollection,
  blog: blogCollection,
};
