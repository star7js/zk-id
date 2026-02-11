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

export const collections = {
  docs: docsCollection,
};
