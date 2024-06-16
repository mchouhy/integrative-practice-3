export const calcTotal = (products) => {
  let total = 0;

  products.forEach((item) => {
    total += item.product.price * item.quantity;
  });

  return total;
};
