package com.example.demo;

import com.example.demo.controllers.OrderController;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.persistence.repositories.OrderRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OrderControllerTest {
    @InjectMocks
    private OrderController orderController;

    @Mock
    private OrderRepository orderRepository;

    @Mock
    private UserRepository userRepository;

    @Before
    public void setUp(){
        Item item = new Item();
        item.setId(1L);
        item.setName("Round Widget");
        BigDecimal price = BigDecimal.valueOf(2.99);
        item.setPrice(price);
        item.setDescription("A widget that is round");
        List<Item> items = new ArrayList<Item>();
        items.add(item);

        User user = new User();
        Cart cart = new Cart();
        user.setId(0);
        user.setUsername("test");
        user.setPassword("testPassword");
        cart.setId(0L);
        cart.setUser(user);
        cart.setItems(items);
        BigDecimal total = BigDecimal.valueOf(2.99);
        cart.setTotal(total);
        user.setCart(cart);
        when(userRepository.findByUsername("test")).thenReturn(user);
        when(userRepository.findByUsername("ege")).thenReturn(null);
    }

    @Test
    public void shouldGetOrders() {
        ResponseEntity<List<UserOrder>> ordersForUser = orderController.getOrdersForUser("test");
        assertNotNull(ordersForUser);
        assertEquals(200, ordersForUser.getStatusCodeValue());
        List<UserOrder> orders = ordersForUser.getBody();
        assertNotNull(orders);

    }

    @Test
    public void shouldNotGetOrdersWhenUserNotFound() {
        ResponseEntity<List<UserOrder>> ordersForUser = orderController.getOrdersForUser("ege");
        assertNotNull(ordersForUser);
        assertEquals(404, ordersForUser.getStatusCodeValue());

    }

    @Test
    public void shouldNotSubmitOrderWhenUserNotFound() {
        ResponseEntity<UserOrder> response = orderController.submit("ege");
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void shouldSubmitOrder() {
        ResponseEntity<UserOrder> response = orderController.submit("test");
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        UserOrder order = response.getBody();
        assertNotNull(order);
        assertEquals(1, order.getItems().size());
    }
}
